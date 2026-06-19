// clawpatrol-plugin-aws gates calls to the AWS APIs across many accounts.
//
// It terminates the agent's TLS, parses each request into an `aws` facet
// (service / action / region / resource / account) so rules can match AWS
// operations by name, selects the target account from the agent's request,
// assumes a per-account role with a single base key, re-signs the request
// with SigV4, and forwards it to AWS through the gateway's brokered dial.
//
// Multi-account model: one base IAM key (in a hub account) plus a role of
// the same name in each member account that the base key may assume. The
// agent picks the account by the access key id in its per-account AWS
// profile — the operator sets that to encode the 12-digit account id, e.g.
// access_key_id = "AKIA<account-id>0000". The agent's secret can be any
// placeholder; the gateway strips the agent's signature and re-signs with
// the assumed-role credentials.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/denoland/clawpatrol/pluginsdk"
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    "aws",
		Version: "0.3.5",
		// No network of its own: every upstream connection — the API call
		// and the STS AssumeRole — is the gateway's audited brokered dial.
		Capabilities: pluginsdk.Capabilities{
			Network: pluginsdk.NetworkNone,
			Egress:  []string{"*.amazonaws.com:443"},
		},
		Facets:      []pluginsdk.FacetDef{awsFacet},
		Credentials: []pluginsdk.CredentialDef{awsAccountCredential},
		Endpoints:   []pluginsdk.EndpointDef{awsAPIEndpoint},
	})
}

// awsFacet is the rule-matching vocabulary for AWS API operations, e.g.
// `aws.account == "035475582903" && aws.action.startsWith("Delete")`.
var awsFacet = pluginsdk.FacetDef{
	Name: "aws",
	Fields: []pluginsdk.FacetField{
		{Name: "service", Kind: pluginsdk.FacetString, Label: "Service", Description: "AWS service", DetailOnly: true},
		{Name: "action", Kind: pluginsdk.FacetString, Label: "Action", Description: "API action (CloudTrail)", DetailOnly: true},
		// Compact-row order is declaration order of the non-title,
		// non-detail_only fields: resource, then account (account_name
		// follows below). region is redundant with the host shown alongside,
		// so it's detail-only — the row reads "<resource> · <account> ·
		// <account_name>" rather than leading with the bare account id.
		{Name: "resource", Kind: pluginsdk.FacetString, Label: "Resource", Description: "Resource ARN / key", Optional: true},
		{Name: "account", Kind: pluginsdk.FacetString, Label: "Account", Description: "AWS account ID"},
		{Name: "region", Kind: pluginsdk.FacetString, Label: "Region", Description: "AWS region", Optional: true, DetailOnly: true},
		{Name: "method", Kind: pluginsdk.FacetString, Label: "Method", Description: "HTTP method", Optional: true, DetailOnly: true},
		// iam_action and account_name are deliberately NOT Optional. The
		// gateway zero-fills omitted *optional* fields to "" (so rules need no
		// has() guard); a non-optional field that the plugin omits instead
		// stays absent, so a rule referencing it sees a CEL unknown and fails
		// closed, while rules that don't reference it are unaffected. The
		// plugin omits these two exactly when their value can't be trusted
		// (iam_action undeterminable; account_name unresolvable from
		// Organizations) — fail-closed is the wanted behavior there.
		// iam_action is the Title: the activity-log verb is the IAM action
		// (e.g. "s3:ListBucket"), not the bare HTTP method.
		{Name: "iam_action", Kind: pluginsdk.FacetString, Label: "IAM action", Description: "IAM action — match with aws.iam_action", Title: true},
		{Name: "account_name", Kind: pluginsdk.FacetString, Label: "Account name", Description: "Account name (Organizations)"},
	},
	// ResultFields is reported after the response via Conn.SetResult. status
	// (the Title) becomes the action's status slot: the HTTP code on success,
	// the AWS error code (e.g. "AccessDenied") on failure.
	ResultFields: []pluginsdk.FacetField{
		{Name: "status", Kind: pluginsdk.FacetString, Label: "Status", Description: "HTTP status, or AWS error code on failure", Title: true},
	},
}

// awsAccountCredential holds a base key (in a hub account) that the endpoint
// uses to assume each member account's role. More than one may be bound to an
// endpoint: `accounts` tags which accounts a key serves, and a credential with
// no `accounts` is the catch-all (see selectBaseKey). A single untagged
// credential — the common case — serves every account.
var awsAccountCredential = pluginsdk.CredentialDef{
	TypeName: "aws_account",
	Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
		// 12-digit account ids this key's role-assumption serves; empty = the
		// fallback key for any account no other credential claims.
		{Name: "accounts", TypeString: "list(string)"},
	}},
	Build: func(req pluginsdk.BuildRequest) (any, error) {
		var cfg struct {
			Accounts []string `json:"accounts"`
		}
		_ = json.Unmarshal(req.ConfigJSON, &cfg)
		return pluginsdk.CredentialBuildResult{
			Canonical: map[string]any{"accounts": cfg.Accounts},
			Metadata: pluginsdk.CredentialMetadata{
				SecretSlots: []pluginsdk.SecretSlot{
					{Name: "access_key_id", Label: "Base AWS access key ID"},
					{Name: "secret_access_key", Label: "Base AWS secret access key"},
					{Name: "session_token", Label: "Base AWS session token (optional)"},
				},
			},
		}, nil
	},
}

// awsAPIEndpoint terminates TLS, evaluates the parsed action, assumes the
// per-account role, re-signs, and brokered-dials AWS.
var awsAPIEndpoint = pluginsdk.EndpointDef{
	TypeName: "aws_api",
	Family:   "aws",
	TLSMode:  pluginsdk.TLSTerminate,
	Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
		{Name: "role", TypeString: "string", Required: true}, // role name assumed in each account
		{Name: "region", TypeString: "string"},               // default STS/signing region
	}},
	HandleConn: handleAWS,
}

type endpointConfig struct {
	Role   string `json:"role"`
	Region string `json:"region"`
}

// maxRequestBody bounds how much of a request body the plugin buffers in
// memory to re-sign it. Larger objects need multipart/streaming uploads,
// which aren't supported yet.
const maxRequestBody = 256 << 20 // 256 MiB

func handleAWS(ctx context.Context, conn *pluginsdk.Conn) error {
	var cfg endpointConfig
	_ = json.Unmarshal(conn.EndpointCanonicalConfig, &cfg)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	// Honor Expect: 100-continue before reading the body. Uploads (S3
	// PutObject and friends) send the request headers with
	// "Expect: 100-continue" and wait for an interim 100 response before
	// streaming the body. http.ReadRequest doesn't emit that for us, so
	// without it the io.ReadAll(req.Body) below deadlocks against the
	// waiting client and the connection eventually closes with no response.
	if expectsContinue(req.Header.Get("Expect")) {
		_, _ = conn.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
	}
	host := req.Host
	if host == "" {
		host = conn.UpstreamHost
	}
	service, region := parseServiceRegion(host)
	if region == "" {
		region = cfg.Region
	}

	// Read the body before parsing the action: query-protocol services
	// (ec2, iam, sts, autoscaling, rds, cloudformation, sqs, sns, ...) put
	// the operation name in the form-encoded body of a POST, so parseAction
	// needs it to avoid classifying every such call as "POST /".
	//
	// The whole body is buffered because re-signing needs the payload hash;
	// cap it so a multi-GiB upload can't OOM the gateway. Larger objects
	// need multipart/streaming, which isn't supported yet.
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	_ = req.Body.Close()
	if int64(len(body)) > maxRequestBody {
		return writeStatus(conn, http.StatusRequestEntityTooLarge,
			"clawpatrol: request body exceeds the gateway buffer limit; large object uploads are not yet supported")
	}

	// S3 uploads stream the body in aws-chunked content-encoding — each
	// chunk length-prefixed, with a per-chunk signature tied to the agent's
	// original SigV4 seed (or an unsigned-trailer variant). We re-sign as a
	// plain payload, so decode the framing back to the raw content and drop
	// the chunked headers; otherwise the body S3 receives doesn't match the
	// hash/length we sign (SignatureDoesNotMatch).
	if isAWSChunked(req.Header) {
		decoded, derr := decodeAWSChunked(body)
		if derr != nil {
			return fmt.Errorf("decode aws-chunked body: %w", derr)
		}
		body = decoded
		req.Header.Del("Content-Encoding")
		req.Header.Del("X-Amz-Decoded-Content-Length")
		req.Header.Del("X-Amz-Trailer")
		// The trailing chunk carried the agent's checksum, which we drop with
		// the framing. Remove the checksum-declaring headers too so the
		// re-signed plain PutObject doesn't promise a checksum we won't send.
		req.Header.Del("X-Amz-Sdk-Checksum-Algorithm")
		for _, k := range headerKeys(req.Header) {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-checksum-") {
				req.Header.Del(k)
			}
		}
		req.ContentLength = int64(len(body))
	}

	action := parseAction(req, body, service)
	account := accountFromAuthorization(req.Header.Get("Authorization"))

	if account == "" {
		return writeStatus(conn, http.StatusForbidden,
			"clawpatrol: could not determine the target AWS account from the request access key id "+
				"(set the agent's access_key_id to encode the account, e.g. AKIA<account-id>0000)")
	}

	// The base key (in a hub account) assumes the target account's role and
	// also drives Organizations account-name resolution, so it is needed
	// before the policy evaluation. With several bound credentials it is the
	// one whose `accounts` covers this account (else the fallback).
	base, err := selectBaseKey(conn, account)
	if err != nil {
		return writeStatus(conn, http.StatusForbidden, "clawpatrol: "+err.Error())
	}
	if base.AccessKeyID == "" || base.SecretAccessKey == "" {
		return fmt.Errorf("no base AWS credentials bound (need an aws_account credential)")
	}

	fields := map[string]any{
		"service":  service,
		"action":   action, // CloudTrail eventName, e.g. DeleteObject
		"verb":     action, // drives the activity-log verb column
		"account":  account,
		"region":   region,
		"resource": req.URL.Path,
		"method":   req.Method,
	}
	if iam := iamAction(service, action); iam != "" {
		fields["iam_action"] = iam // e.g. s3:DeleteObject, s3:ListBucket
	}
	// account_name comes from AWS Organizations. Omit it when it can't be
	// resolved: a rule matching aws.account_name then evaluates to a CEL
	// unknown and fails closed, while rules that don't reference it are
	// unaffected.
	acctName, known := org.accountName(ctx, conn, base, cfg.Role, account)
	if known {
		fields["account_name"] = acctName
	}

	verdict, err := conn.Evaluate(ctx, "aws", fields,
		approvalSummary(req, service, action, region, account, acctName, host))
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	if !allowed(verdict.Action) {
		return writeStatus(conn, http.StatusForbidden, "clawpatrol: denied by policy")
	}

	// Assume the per-account role with the base key, then sign with the
	// temporary credentials.
	creds, err := assumeRole(ctx, conn, base, account, cfg.Role, "clawpatrol-"+conn.Profile)
	if err != nil {
		return fmt.Errorf("assume role: %w", err)
	}
	if err := signRequest(ctx, req, host, body, service, region, creds); err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	up, err := conn.DialUpstream(ctx, "tcp", host+":443", &pluginsdk.DialUpstreamOptions{TLS: true, TLSServerName: host})
	if err != nil {
		return fmt.Errorf("dial %s: %w", host, err)
	}
	defer func() { _ = up.Close() }()
	if err := req.Write(up); err != nil {
		return fmt.Errorf("write upstream: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Report the outcome. On success the status is the HTTP code; on a 4xx/5xx
	// the AWS error code (e.g. "AccessDenied") is far more useful, so buffer
	// the error body to extract it, then restore it (re-framed to its length)
	// so the agent still gets the response. AWS error bodies are small; the
	// 256 KiB cap bounds memory, and an error body beyond it is forwarded
	// truncated rather than buffered unbounded — a non-issue in practice.
	status := strconv.Itoa(resp.StatusCode)
	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.ContentLength = int64(len(errBody))
		if code := awsErrorCode(resp.Header, errBody); code != "" {
			status = code
		}
	}
	_ = conn.SetResult(ctx, map[string]any{"status": status})
	return resp.Write(conn)
}

// expectsContinue reports whether the Expect header requests a 100-continue
// interim response (case-insensitive, per RFC 7231).
func expectsContinue(expect string) bool {
	return strings.EqualFold(strings.TrimSpace(expect), "100-continue")
}

// approvalSummary builds the human-facing one-line description of an AWS
// operation for the HITL approval prompt. It surfaces the method, the full
// resource (host + path, so the bucket/key or API host is visible), the
// region, and the account — and the parsed operation name for query/JSON
// services (ec2 TerminateInstances, etc.) where the method+path alone
// ("POST /") says nothing. REST services (S3) omit the redundant operation
// name since it's just "METHOD path".
func approvalSummary(req *http.Request, service, action, region, account, acctName, host string) string {
	resource := host + req.URL.Path
	op := ""
	if action != "" && action != req.Method+" "+req.URL.Path {
		op = " [" + action + "]"
	}
	// Lead with the account name when configured ("dev (676206942143)"),
	// falling back to the bare id, so an approver sees which account at a
	// glance.
	acct := account
	if acctName != "" {
		acct = acctName + " (" + account + ")"
	}
	if region != "" {
		acct += " " + region
	}
	return fmt.Sprintf("%s %s %s%s in account %s", req.Method, service, resource, op, acct)
}

// signRequest replaces *req with a freshly built upstream request for host,
// carrying body and only the operation-relevant headers, signed with creds.
//
// Re-signing the agent's own *http.Request in place is fragile: it arrives
// via http.ReadRequest carrying transport/streaming headers (Expect,
// Accept-Encoding, aws-chunked framing, the agent's placeholder
// Authorization/x-amz-content-sha256) and parser state that make SignHTTP
// cover header values the subsequent req.Write serializes differently —
// S3 then rejects with SignatureDoesNotMatch. Building a clean request and
// copying only the headers that are part of the S3 operation keeps the
// signed canonical request and the bytes on the wire identical.
func signRequest(ctx context.Context, req *http.Request, host string, body []byte, service, region string, creds aws.Credentials) error {
	out, err := http.NewRequestWithContext(ctx, req.Method, "https://"+host+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	out.ContentLength = int64(len(body))
	for k, vs := range req.Header {
		if signerControlledHeader(k) {
			continue
		}
		out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	out.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(ctx, creds, out, hash, service, region, time.Now()); err != nil {
		return err
	}
	*req = *out
	return nil
}

// signerControlledHeader reports whether a request header is one the gateway
// owns and must not copy verbatim from the agent: SigV4 auth/identity and
// payload-hash headers that the re-sign recomputes, content-length and host
// that come from the request fields, and hop-by-hop transport headers. Every
// other header (Content-Type, Range, conditional, SSE, copy-source, ACL
// grants, x-amz-meta-*, checksums, ...) is part of the operation's semantics
// and is forwarded and signed as sent — an allow-list would silently drop
// operation-affecting headers (wrong bytes from a Range GET, an object stored
// unencrypted when SSE headers vanish, a broken CopyObject).
func signerControlledHeader(k string) bool {
	switch strings.ToLower(k) {
	case "authorization", "x-amz-date", "x-amz-security-token",
		"x-amz-content-sha256", "content-length", "host", "expect",
		"user-agent", "accept-encoding",
		"connection", "proxy-connection", "keep-alive",
		"transfer-encoding", "te", "trailer", "upgrade":
		return true
	}
	return false
}

func allowed(action string) bool {
	return action == "allow" || action == "hitl_allow"
}

// baseKey reads the base signing key from the bound credential's extras
// (the same multi-slot delivery the built-in AWS credential uses).
func baseKey(conn *pluginsdk.Conn) aws.Credentials {
	ex := conn.CredentialExtras
	return aws.Credentials{
		AccessKeyID:     ex["access_key_id"],
		SecretAccessKey: ex["secret_access_key"],
		SessionToken:    ex["session_token"],
	}
}

func writeStatus(conn *pluginsdk.Conn, code int, msg string) error {
	resp := &http.Response{
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(msg + "\n")),
		ContentLength: int64(len(msg) + 1),
	}
	return resp.Write(conn)
}

var (
	xmlErrCodeRe  = regexp.MustCompile(`<Code>([^<]+)</Code>`)
	jsonErrTypeRe = regexp.MustCompile(`"__type"\s*:\s*"([^"]+)"`)
	jsonErrCodeRe = regexp.MustCompile(`"[Cc]ode"\s*:\s*"([^"]+)"`)
)

// awsErrorCode pulls the AWS error code from an error response: the
// x-amzn-errortype header (query / JSON APIs), the XML <Code> (S3, EC2,
// query), or a JSON __type / code field. "" when none is found, so the
// caller falls back to the HTTP status.
func awsErrorCode(h http.Header, body []byte) string {
	if et := h.Get("X-Amzn-Errortype"); et != "" {
		// e.g. "AccessDeniedException:http://internal.amazon.com/...".
		if i := strings.IndexByte(et, ':'); i > 0 {
			et = et[:i]
		}
		return strings.TrimSpace(et)
	}
	s := string(body)
	if m := xmlErrCodeRe.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	if m := jsonErrTypeRe.FindStringSubmatch(s); len(m) == 2 {
		t := m[1]
		// "...ServiceException#AccessDeniedException" -> "AccessDeniedException".
		if i := strings.LastIndexByte(t, '#'); i >= 0 {
			t = t[i+1:]
		}
		return t
	}
	if m := jsonErrCodeRe.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}
