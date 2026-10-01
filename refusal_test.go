package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// scriptedConn is a net.Conn whose reads replay a fixed request and whose
// writes land in a buffer. It stands in for the gateway-terminated agent
// connection so handleAWS can be driven end to end without a gateway. A Conn
// built outside the SDK carries no emit / evaluate / dial hooks, which is also
// the worst case for a refusal: nothing the plugin reports can be delivered,
// and the agent must still be answered.
type scriptedConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newScriptedConn(request string) *scriptedConn {
	return &scriptedConn{in: bytes.NewReader([]byte(request))}
}

func (c *scriptedConn) Read(p []byte) (int, error)       { return c.in.Read(p) }
func (c *scriptedConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }
func (c *scriptedConn) response(t *testing.T) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(c.out.Bytes())), nil)
	if err != nil {
		t.Fatalf("agent got no parseable response (%d bytes written): %v", c.out.Len(), err)
	}
	return resp
}

// signedPost builds the wire bytes of the probe from the issue: a SigV4-signed
// POST whose URL names one operation and whose body names another.
func signedPost(rawQuery, body string) string {
	req := "POST /"
	if rawQuery != "" {
		req += "?" + rawQuery
	}
	return req + " HTTP/1.1\r\n" +
		"Host: ec2.us-east-1.amazonaws.com\r\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIA035475582903XXXX/20240101/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=ab\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
}

func awsEndpointConn(c net.Conn) *pluginsdk.Conn {
	cfg, _ := json.Marshal(endpointConfig{Role: "clawpatrol", Region: "us-east-1"})
	return &pluginsdk.Conn{
		Conn:                    c,
		EndpointTypeName:        "aws_api",
		EndpointCanonicalConfig: cfg,
		Profile:                 "agent",
		UpstreamHost:            "ec2.us-east-1.amazonaws.com",
		CredentialTypeName:      "aws_account",
		CredentialExtras: map[string]string{
			"access_key_id":     "AKIAHUBBASEKEY000000",
			"secret_access_key": "hub-secret",
		},
	}
}

// TestHandleAWSRefusesConflictingOperationNames is the issue's probe: a signed
// POST to ?Action=DescribeRegions whose body says Action=TerminateInstances.
// It must still be answered 403, naming both operations, with no verdict asked
// for and no upstream reached — the dial hook is nil, so any attempt to
// forward would surface as an error instead of a response.
func TestHandleAWSRefusesConflictingOperationNames(t *testing.T) {
	sc := newScriptedConn(signedPost("Action=DescribeRegions", "Action=TerminateInstances&Version=2016-11-15"))
	if err := handleAWS(context.Background(), awsEndpointConn(sc)); err != nil {
		t.Fatalf("handleAWS err = %v, want nil (the refusal is a response, not a handler failure)", err)
	}
	resp := sc.response(t)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	var msg bytes.Buffer
	_, _ = msg.ReadFrom(resp.Body)
	for _, want := range []string{"conflicting operation names", "DescribeRegions", "TerminateInstances"} {
		if !strings.Contains(msg.String(), want) {
			t.Errorf("403 body %q does not mention %q", msg.String(), want)
		}
	}
}

// TestHandleAWSAgreeingOperationNamesReachEvaluation is the other half: a
// request that names one operation consistently is not touched by the refusal
// path. With no gateway wired, Conn.Evaluate is the first thing that cannot be
// served, so reaching it is the proof the request was carried all the way to
// the policy decision rather than short-circuited.
func TestHandleAWSAgreeingOperationNamesReachEvaluation(t *testing.T) {
	// Serve the Organizations account-name lookup from a fresh (empty) cache
	// so the handler does not try to resolve a name over the absent dial.
	prevNames, prevFetched := org.names, org.fetchedAt
	org.names, org.fetchedAt = map[string]string{}, time.Now()
	t.Cleanup(func() { org.names, org.fetchedAt = prevNames, prevFetched })

	sc := newScriptedConn(signedPost("", "Action=DescribeRegions&Version=2016-11-15"))
	err := handleAWS(context.Background(), awsEndpointConn(sc))
	if err == nil || !strings.Contains(err.Error(), "Conn.Evaluate not wired") {
		t.Fatalf("handleAWS err = %v, want the evaluation to be reached", err)
	}
	if sc.out.Len() != 0 {
		t.Fatalf("agent was answered %q before the evaluation", sc.out.String())
	}
}

// TestRefusalEventIsAnHonestDeny pins what the action record says: a deny
// attributed to no rule, the refusal as its reason, the facts the host and
// request line carry — and no operation name, because none was determined.
func TestRefusalEventIsAnHonestDeny(t *testing.T) {
	req := &http.Request{
		Method: "POST",
		Header: http.Header{},
		URL:    &url.URL{Path: "/", RawQuery: "Action=DescribeRegions"},
	}
	ev := refusalEvent(req, "ec2", "us-east-1", "035475582903", "ec2.us-east-1.amazonaws.com",
		"request carries conflicting operation names (DescribeRegions, TerminateInstances)")

	if ev.Action != "deny" {
		t.Errorf("Action = %q, want %q", ev.Action, "deny")
	}
	if ev.Rule != "" {
		t.Errorf("Rule = %q, want empty: no rule produced this verdict", ev.Rule)
	}
	if !strings.Contains(ev.Reason, "conflicting operation names") {
		t.Errorf("Reason = %q, does not carry the refusal", ev.Reason)
	}
	if !strings.Contains(ev.Summary, "ec2.us-east-1.amazonaws.com") {
		t.Errorf("Summary = %q, does not describe the request", ev.Summary)
	}
	// Omitted rather than guessed: a name here would read as a real call.
	for _, absent := range []string{"action", "iam_action", "account_name"} {
		if _, ok := ev.Facets[absent]; ok {
			t.Errorf("Facets[%q] = %v, want absent", absent, ev.Facets[absent])
		}
	}
	for field, want := range map[string]string{
		"service":  "ec2",
		"region":   "us-east-1",
		"resource": "/",
		"method":   "POST",
		"account":  "035475582903",
	} {
		if got := ev.Facets[field]; got != want {
			t.Errorf("Facets[%q] = %v, want %q", field, got, want)
		}
	}
}

// TestRefusalEventOmitsUnknownAccount keeps the non-optional aws.account field
// absent when the request's access key id encodes no account, rather than
// reporting an empty one as fact.
func TestRefusalEventOmitsUnknownAccount(t *testing.T) {
	req := &http.Request{Method: "POST", Header: http.Header{}, URL: &url.URL{Path: "/"}}
	ev := refusalEvent(req, "ec2", "us-east-1", "", "ec2.us-east-1.amazonaws.com", "refused")
	if _, ok := ev.Facets["account"]; ok {
		t.Errorf("Facets[\"account\"] = %v, want absent", ev.Facets["account"])
	}
}

// TestRefusalEventClampsAgentWrittenFields covers the rest of the record. The
// method and the host the service and region are read off are the agent's to
// make as long as it likes — http.ReadRequest bounds neither — and the gateway
// persists every value here verbatim.
func TestRefusalEventClampsAgentWrittenFields(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)
	req := &http.Request{
		Method: huge,
		Header: http.Header{},
		URL:    &url.URL{Path: "/" + huge},
	}
	ev := refusalEvent(req, huge, huge, "035475582903", huge+".amazonaws.com", "refused")

	if len(ev.Summary) > maxAuditSummary+len("…") {
		t.Errorf("Summary is %d bytes, want at most %d", len(ev.Summary), maxAuditSummary+len("…"))
	}
	// Clamped, not dropped: the marker proves the field was cut rather than
	// emptied, so the length assertions below are not passing trivially.
	for field, v := range map[string]any{"service": ev.Facets["service"], "method": ev.Facets["method"], "Summary": ev.Summary} {
		if s, _ := v.(string); !strings.HasSuffix(s, "…") {
			t.Errorf("%s = %q, want a clamp marker", field, s)
		}
	}
	if len(ev.Verb) > maxAuditField+len("…") {
		t.Errorf("Verb is %d bytes, want at most %d", len(ev.Verb), maxAuditField+len("…"))
	}
	for field, v := range ev.Facets {
		s, ok := v.(string)
		if !ok {
			t.Errorf("Facets[%q] = %v, want a string", field, v)
			continue
		}
		if len(s) > maxAuditField+len("…") {
			t.Errorf("Facets[%q] is %d bytes, want at most %d", field, len(s), maxAuditField+len("…"))
		}
	}
}

// TestRefusalEventKeepsClampedValuesValidUTF8 drives multi-byte runes through
// the clamp. The resource and the summary built around it carry whatever the
// agent wrote in the request line, and the gateway marshals the record to JSON,
// so a cut landing inside a rune would leave a byte for it to coerce.
func TestRefusalEventKeepsClampedValuesValidUTF8(t *testing.T) {
	// A 3-byte rune repeated past every bound, so a cut at any byte offset
	// divisible by neither 3 nor the bound lands mid-rune unless clamp backs up.
	huge := strings.Repeat("é€世", 4096)
	req := &http.Request{Method: "POST", Header: http.Header{}, URL: &url.URL{Path: "/" + huge}}
	ev := refusalEvent(req, "ec2", "us-east-1", "035475582903", huge+".amazonaws.com", "refused")

	vals := map[string]string{"Summary": ev.Summary, "Verb": ev.Verb}
	for field, v := range ev.Facets {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("Facets[%q] = %v, want a string", field, v)
		}
		vals["Facets["+field+"]"] = s
	}
	for field, s := range vals {
		if !utf8.ValidString(s) {
			t.Errorf("%s = %q is not valid UTF-8; the clamp cut inside a rune", field, s)
		}
	}
	if !strings.HasSuffix(ev.Facets["resource"].(string), "…") {
		t.Errorf("resource = %q, want a clamp marker", ev.Facets["resource"])
	}
}

// TestHandleAWSRefusesConflictWithOversizedRequestLine pairs the probe with a
// megabyte-long host. The refusal is unchanged and what the agent is told stays
// small; what the record would carry is pinned by
// TestRefusalEventClampsAgentWrittenFields.
func TestHandleAWSRefusesConflictWithOversizedRequestLine(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)
	body := "Action=DescribeRegions&Action=TerminateInstances"
	raw := "POST /?Action=ListBuckets HTTP/1.1\r\n" +
		"Host: " + huge + ".ec2.us-east-1.amazonaws.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body

	sc := newScriptedConn(raw)
	if err := handleAWS(context.Background(), awsEndpointConn(sc)); err != nil {
		t.Fatalf("handleAWS err = %v, want nil", err)
	}
	if got := sc.response(t).StatusCode; got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	if sc.out.Len() > 4096 {
		t.Errorf("refusal response is %d bytes; it repeats back more than the refusal", sc.out.Len())
	}
}

// TestConflictingOperationRefusalIsBounded covers the agent's side of the
// record: both names are the agent's to choose and the gateway persists the
// reason verbatim, so the refusal is clamped in length and in count.
func TestConflictingOperationRefusalIsBounded(t *testing.T) {
	long := func(suffix string) string {
		return "Describe" + strings.Repeat("A", 4096) + suffix
	}
	var params []string
	for i := 0; i < 500; i++ {
		params = append(params, "Action="+long(fmt.Sprintf("X%d", i)))
	}
	req := &http.Request{Method: "POST", Header: http.Header{}, URL: &url.URL{Path: "/"}}
	_, err := parseAction(req, []byte(strings.Join(params, "&")), "ec2")
	if err == nil {
		t.Fatal("parseAction allowed a request naming 500 distinct operations")
	}
	if len(err.Error()) > 512 {
		t.Errorf("refusal is %d bytes; an agent-chosen string this long reaches the action record", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("refusal %q does not mark what it left out", err.Error())
	}
}

// TestClampedNamesStillConflict is the clamp's safety property: names are
// compared whole and clamped only for display. Two operations that differ
// solely past the display clamp are still two operations, and collapsing them
// would turn this refusal into a forwarded request.
func TestClampedNamesStillConflict(t *testing.T) {
	prefix := "Describe" + strings.Repeat("A", maxOperationNameChars*2)
	body := "Action=" + prefix + "X&Action=" + prefix + "Y"
	req := &http.Request{Method: "POST", Header: http.Header{}, URL: &url.URL{Path: "/"}}
	if got, err := parseAction(req, []byte(body), "ec2"); err == nil {
		t.Fatalf("parseAction = %q, want a refusal: the two names differ only past the clamp", got)
	}
}

// TestCollectionCapKeepsAgreeingNamesSingular guards the other direction of
// the collection cap: a name repeated far more often than the cap is still one
// name, so an ordinary request is not refused by the bound.
func TestCollectionCapKeepsAgreeingNamesSingular(t *testing.T) {
	var params []string
	for i := 0; i < maxCollectedOperationNames*20; i++ {
		params = append(params, "Action=DescribeRegions")
	}
	req := &http.Request{Method: "POST", Header: http.Header{}, URL: &url.URL{Path: "/"}}
	got, err := parseAction(req, []byte(strings.Join(params, "&")), "ec2")
	if err != nil {
		t.Fatalf("parseAction refused a request naming one operation %d times: %v", maxCollectedOperationNames*20, err)
	}
	if got != "DescribeRegions" {
		t.Errorf("parseAction = %q, want %q", got, "DescribeRegions")
	}
}

// TestDescribeOperationNames pins the rendering the refusal text is built on.
func TestDescribeOperationNames(t *testing.T) {
	long := strings.Repeat("A", maxOperationNameChars+10)
	cases := []struct {
		name  string
		names []string
		want  string
	}{
		{"two short", []string{"DescribeRegions", "TerminateInstances"}, "DescribeRegions, TerminateInstances"},
		{"clamped", []string{long}, long[:maxOperationNameChars] + "…"},
		{"capped count", []string{"A", "B", "C", "D", "E"}, "A, B, C, D, …"},
	}
	for _, c := range cases {
		if got := describeOperationNames(c.names); got != c.want {
			t.Errorf("%s: describeOperationNames = %q, want %q", c.name, got, c.want)
		}
	}
}
