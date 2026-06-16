// clawpatrol-plugin-aws gates calls to the AWS APIs. It terminates the
// agent's TLS, parses each request into an `aws` facet (service / action /
// region / resource) so rules can match AWS operations by name, signs the
// request with SigV4 using a per-account credential, and forwards it to
// AWS through the gateway's brokered dial. Multiple AWS accounts are
// multiple `aws_account` credential instances.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		// The plugin holds no network of its own — every upstream
		// connection is the gateway's brokered dial, restricted to AWS.
		Capabilities: pluginsdk.Capabilities{
			Network: pluginsdk.NetworkNone,
			Egress:  []string{"*.amazonaws.com:443"},
		},
		Facets:      []pluginsdk.FacetDef{awsFacet},
		Credentials: []pluginsdk.CredentialDef{awsAccountCredential},
		Endpoints:   []pluginsdk.EndpointDef{awsAPIEndpoint},
	})
}

// awsFacet is the rule-matching vocabulary for AWS API operations. A rule
// reads e.g. `aws.service == "s3" && aws.action == "DeleteObject"`.
var awsFacet = pluginsdk.FacetDef{
	Name: "aws",
	Fields: []pluginsdk.FacetField{
		{Name: "service", Kind: pluginsdk.FacetString, Label: "Service"},
		{Name: "action", Kind: pluginsdk.FacetString, Label: "Action"},
		{Name: "region", Kind: pluginsdk.FacetString, Label: "Region", Optional: true},
		{Name: "resource", Kind: pluginsdk.FacetString, Label: "Resource", Optional: true},
		{Name: "method", Kind: pluginsdk.FacetString, Label: "Method", Optional: true},
	},
}

// awsAccountCredential is one AWS account's signing identity. Multiple
// accounts = multiple credential instances, each bound to the endpoints
// that should use it.
var awsAccountCredential = pluginsdk.CredentialDef{
	TypeName: "aws_account",
	Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
		{Name: "region", TypeString: "string"}, // default region when the host doesn't carry one
	}},
	Build: func(_ pluginsdk.BuildRequest) (any, error) {
		// Declare the dashboard secret inputs the gateway collects and
		// delivers (as the credential secret + extras) at request time.
		return pluginsdk.CredentialBuildResult{
			Canonical: map[string]any{},
			Metadata: pluginsdk.CredentialMetadata{
				SecretSlots: []pluginsdk.SecretSlot{
					{Name: "access_key_id", Label: "AWS access key ID"},
					{Name: "secret_access_key", Label: "AWS secret access key"},
					{Name: "session_token", Label: "AWS session token (optional)"},
				},
			},
		}, nil
	},
}

// awsAPIEndpoint terminates TLS, evaluates the parsed `aws` action, signs,
// and brokered-dials AWS.
var awsAPIEndpoint = pluginsdk.EndpointDef{
	TypeName:   "aws_api",
	Family:     "aws", // bind rules to the aws facet above
	TLSMode:    pluginsdk.TLSTerminate,
	HandleConn: handleAWS,
}

func handleAWS(ctx context.Context, conn *pluginsdk.Conn) error {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	host := req.Host
	if host == "" {
		host = conn.UpstreamHost
	}
	service, region := parseServiceRegion(host)
	if region == "" {
		region = credentialRegion(conn)
	}
	action := parseAction(req)

	// Buffer the body so we can hash it for signing and replay it upstream.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	_ = req.Body.Close()

	// Ask the gateway to rule on the operation against the aws facet.
	verdict, err := conn.Evaluate(ctx, "aws", map[string]any{
		"service":  service,
		"action":   action,
		"region":   region,
		"resource": req.URL.Path,
		"method":   req.Method,
	}, req.Method+" "+service+":"+action)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	if !allowed(verdict.Action) {
		return writeStatus(conn, http.StatusForbidden, "clawpatrol: denied by policy")
	}

	// Sign with SigV4 using the bound account's credentials.
	if err := signRequest(ctx, req, host, body, service, region, conn); err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	// Forward to AWS through the gateway's brokered dial (TLS-terminated
	// upstream, real cert verification), then relay the response.
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

func signRequest(ctx context.Context, req *http.Request, host string, body []byte, service, region string, conn *pluginsdk.Conn) error {
	ak, sk, st := awsKeys(conn)
	if ak == "" || sk == "" {
		return fmt.Errorf("no AWS credentials bound (need an aws_account credential)")
	}
	// Reconstruct the absolute URL the signer and the upstream write need.
	req.URL.Scheme = "https"
	req.URL.Host = host
	req.RequestURI = ""
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	creds := aws.Credentials{AccessKeyID: ak, SecretAccessKey: sk, SessionToken: st}
	return v4.NewSigner().SignHTTP(ctx, creds, req, payloadHash, service, region, time.Now())
}

// allowed reports whether a verdict action permits the request.
func allowed(action string) bool {
	return action == "allow" || action == "hitl_allow"
}

// parseServiceRegion derives the AWS service and region from the host,
// e.g. "dynamodb.us-east-1.amazonaws.com" -> ("dynamodb", "us-east-1"),
// "s3.amazonaws.com" -> ("s3", "").
func parseServiceRegion(host string) (service, region string) {
	host = strings.ToLower(host)
	for _, suffix := range []string{".amazonaws.com"} {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		labels := strings.Split(strings.TrimSuffix(host, suffix), ".")
		if len(labels) == 0 {
			return "", ""
		}
		service = labels[0]
		if len(labels) >= 2 && looksLikeRegion(labels[1]) {
			region = labels[1]
		}
		return service, region
	}
	return "", ""
}

func looksLikeRegion(s string) bool {
	// e.g. us-east-1, eu-west-2, ap-southeast-1.
	return strings.Count(s, "-") >= 2
}

// parseAction extracts the operation name. JSON-protocol services carry
// it in X-Amz-Target ("DynamoDB_20120810.PutItem" -> "PutItem"); query
// services in an Action parameter; otherwise it falls back to METHOD path.
func parseAction(req *http.Request) string {
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		if i := strings.LastIndex(t, "."); i >= 0 {
			return t[i+1:]
		}
		return t
	}
	if a := req.URL.Query().Get("Action"); a != "" {
		return a
	}
	return req.Method + " " + req.URL.Path
}

// awsKeys reads the account's signing material from the bound credential.
// The gateway delivers the declared secret slots in the credential extras.
func awsKeys(conn *pluginsdk.Conn) (accessKey, secretKey, sessionToken string) {
	ex := conn.CredentialExtras
	accessKey = ex["access_key_id"]
	secretKey = ex["secret_access_key"]
	sessionToken = ex["session_token"]
	// Fall back to the primary secret bytes for the secret access key.
	if secretKey == "" {
		secretKey = string(conn.CredentialSecret)
	}
	return accessKey, secretKey, sessionToken
}

func credentialRegion(conn *pluginsdk.Conn) string {
	return conn.CredentialExtras["region"]
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
