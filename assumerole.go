package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/denoland/clawpatrol/pluginsdk"
)

// The plugin holds no network of its own, so the STS AssumeRole call that
// mints a target account's temporary credentials is made *through the
// gateway's brokered dial* — the AWS SDK's HTTP transport dials via
// conn.DialUpstream, so STS traffic is gateway-audited and bounded by the
// egress allow-list (sts.* is covered by *.amazonaws.com).

// stsRegion is the regional STS endpoint we reach (sts.<region>.amazonaws.com).
const stsRegion = "us-east-1"

// assumeRoleSkew refreshes cached credentials this long before they expire.
const assumeRoleSkew = 5 * time.Minute

type cachedCreds struct {
	creds  aws.Credentials
	expiry time.Time
}

// roleCache caches AssumeRole results per role ARN. The temporary
// credentials are account-scoped (not connection-scoped), so the cache is
// process-wide and shared across agent connections.
type roleCache struct {
	mu sync.Mutex
	m  map[string]cachedCreds
}

var assumed = &roleCache{m: map[string]cachedCreds{}}

func (c *roleCache) get(arn string) (aws.Credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[arn]
	if !ok || !time.Now().Before(v.expiry.Add(-assumeRoleSkew)) {
		return aws.Credentials{}, false
	}
	return v.creds, true
}

func (c *roleCache) put(arn string, creds aws.Credentials, expiry time.Time) {
	c.mu.Lock()
	c.m[arn] = cachedCreds{creds: creds, expiry: expiry}
	c.mu.Unlock()
}

// assumeRole returns temporary credentials for the role in accountID,
// assuming it with the base credentials via STS over the connection's
// brokered dial. Results are cached until shortly before expiry.
func assumeRole(ctx context.Context, conn *pluginsdk.Conn, base aws.Credentials, accountID, role, sessionName string) (aws.Credentials, error) {
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, role)
	if c, ok := assumed.get(arn); ok {
		return c, nil
	}

	cfg := aws.Config{
		Region:      stsRegion,
		Credentials: awscreds.NewStaticCredentialsProvider(base.AccessKeyID, base.SecretAccessKey, base.SessionToken),
		HTTPClient:  brokeredHTTPClient(conn),
	}
	out, err := sts.NewFromConfig(cfg).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(arn),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("assume %s: %w", arn, err)
	}
	creds := aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
	expiry := time.Now().Add(time.Hour)
	if out.Credentials.Expiration != nil {
		expiry = *out.Credentials.Expiration
	}
	assumed.put(arn, creds, expiry)
	return creds, nil
}

// brokeredHTTPClient returns an *http.Client whose every connection is the
// gateway's brokered dial (gateway-terminated upstream TLS), so the plugin
// reaches AWS with no socket of its own.
func brokeredHTTPClient(conn *pluginsdk.Conn) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}
				return conn.DialUpstream(ctx, "tcp", addr, &pluginsdk.DialUpstreamOptions{TLS: true, TLSServerName: host})
			},
		},
	}
}
