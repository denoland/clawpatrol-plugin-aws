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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/denoland/clawpatrol/pluginsdk"
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    "aws",
		Version: "0.1.0",
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
		{Name: "service", Kind: pluginsdk.FacetString, Label: "Service"},
		{Name: "action", Kind: pluginsdk.FacetString, Label: "Action"},
		{Name: "account", Kind: pluginsdk.FacetString, Label: "Account"},
		{Name: "region", Kind: pluginsdk.FacetString, Label: "Region", Optional: true},
		{Name: "resource", Kind: pluginsdk.FacetString, Label: "Resource", Optional: true},
		{Name: "method", Kind: pluginsdk.FacetString, Label: "Method", Optional: true},
	},
}

// awsAccountCredential holds the single base key (in the hub account) that
// the endpoint uses to assume each member account's role.
var awsAccountCredential = pluginsdk.CredentialDef{
	TypeName: "aws_account",
	Build: func(_ pluginsdk.BuildRequest) (any, error) {
		return pluginsdk.CredentialBuildResult{
			Canonical: map[string]any{},
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
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	_ = req.Body.Close()

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

	action := parseAction(req, body)
	account := accountFromAuthorization(req.Header.Get("Authorization"))

	if account == "" {
		return writeStatus(conn, http.StatusForbidden,
			"clawpatrol: could not determine the target AWS account from the request access key id "+
				"(set the agent's access_key_id to encode the account, e.g. AKIA<account-id>0000)")
	}

	verdict, err := conn.Evaluate(ctx, "aws", map[string]any{
		"service":  service,
		"action":   action,
		"account":  account,
		"region":   region,
		"resource": req.URL.Path,
		"method":   req.Method,
	}, approvalSummary(req, service, action, region, account, host))
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	if !allowed(verdict.Action) {
		return writeStatus(conn, http.StatusForbidden, "clawpatrol: denied by policy")
	}

	// Assume the per-account role with the base key, then sign with the
	// temporary credentials.
	base := baseKey(conn)
	if base.AccessKeyID == "" || base.SecretAccessKey == "" {
		return fmt.Errorf("no base AWS credentials bound (need an aws_account credential)")
	}
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
func approvalSummary(req *http.Request, service, action, region, account, host string) string {
	resource := host + req.URL.Path
	op := ""
	if action != "" && action != req.Method+" "+req.URL.Path {
		op = " [" + action + "]"
	}
	where := account
	if region != "" {
		where = account + " " + region
	}
	return fmt.Sprintf("%s %s %s%s in account %s", req.Method, service, resource, op, where)
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
		if forwardableUpstreamHeader(k) {
			out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
		}
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

// forwardableUpstreamHeader reports whether a request header from the agent
// is part of the S3 operation's semantics and should be carried (and signed)
// to the upstream. Transport, auth, encoding-framing, and content-hash
// headers are deliberately excluded — the gateway sets those itself.
func forwardableUpstreamHeader(k string) bool {
	switch strings.ToLower(k) {
	case "content-type", "content-md5", "content-language", "content-disposition",
		"cache-control", "expires",
		"x-amz-acl", "x-amz-storage-class", "x-amz-tagging",
		"x-amz-website-redirect-location",
		"x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date",
		"x-amz-object-lock-legal-hold":
		return true
	}
	return strings.HasPrefix(strings.ToLower(k), "x-amz-meta-")
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
