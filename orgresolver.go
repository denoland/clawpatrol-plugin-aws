package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/denoland/clawpatrol/pluginsdk"
)

// Account names come from AWS Organizations, not operator-maintained aliases.
// The plugin learns the org's management account, assumes the configured role
// there, and lists the accounts (id -> name), caching the whole map. When a
// name can't be resolved the caller omits aws.account_name entirely, so a
// rule that matches on it evaluates to a CEL unknown and fails closed, while
// rules that don't reference it are unaffected.

// orgCacheTTL bounds how long a resolved account map is reused before a
// refresh. Account names change rarely; a coarse TTL keeps the per-request
// cost at zero between refreshes.
const orgCacheTTL = 15 * time.Minute

type orgResolver struct {
	mu        sync.Mutex
	names     map[string]string // account id -> name
	fetchedAt time.Time

	// refreshMu single-flights the refresh so a cold or expired cache
	// triggers exactly one resolution chain, not one per concurrent request.
	refreshMu sync.Mutex
}

var org = &orgResolver{}

// accountName returns the Organizations name for accountID and whether it is
// known. It refreshes a process-wide cache of the full account list at most
// once per orgCacheTTL. The refresh is single-flighted: while one request
// resolves, others serve the stale map (if any) without blocking, and on any
// resolution error the stale map is kept. When nothing is cached and
// resolution fails it returns ("", false) — the caller then omits the facet
// field so account-name rules fail closed.
func (r *orgResolver) accountName(ctx context.Context, conn *pluginsdk.Conn, base aws.Credentials, role, accountID string) (string, bool) {
	if name, ok, fresh := r.cached(accountID); fresh {
		return name, ok
	} else if !r.refreshMu.TryLock() {
		// A refresh is already in flight. Serve the stale map if we have one;
		// only block for the result when the cache is cold.
		if r.has() {
			return name, ok
		}
		r.refreshMu.Lock()
		r.refreshMu.Unlock()
		name, ok, _ = r.cached(accountID)
		return name, ok
	}
	defer r.refreshMu.Unlock()

	// We own the refresh. Re-check in case another holder just refreshed.
	if name, ok, fresh := r.cached(accountID); fresh {
		return name, ok
	}

	names, err := fetchOrgAccounts(ctx, conn, base, role)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.names = names
		r.fetchedAt = time.Now()
	}
	name, ok := r.names[accountID] // fresh on success, stale on error, nil-safe
	return name, ok
}

// cached returns the lookup result and whether the cache is currently fresh.
func (r *orgResolver) cached(accountID string) (name string, ok, fresh bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names == nil {
		return "", false, false
	}
	name, ok = r.names[accountID]
	fresh = time.Now().Before(r.fetchedAt.Add(orgCacheTTL))
	return name, ok, fresh
}

func (r *orgResolver) has() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names != nil
}

// fetchOrgAccounts resolves the org's management account and lists every
// account in it, returning an id -> name map. The base key's own account is
// the hub; DescribeOrganization (allowed from any member) names the
// management account; ListAccounts (allowed only from the management account)
// reads the names. Every call rides the connection's brokered dial.
func fetchOrgAccounts(ctx context.Context, conn *pluginsdk.Conn, base aws.Credentials, role string) (map[string]string, error) {
	hub, err := callerAccount(ctx, conn, base)
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}
	hubCreds, err := assumeRole(ctx, conn, base, hub, role, "clawpatrol-orgresolve")
	if err != nil {
		return nil, err
	}
	masterID, err := describeOrgMaster(ctx, conn, hubCreds)
	if err != nil {
		return nil, fmt.Errorf("describe organization: %w", err)
	}
	mgmtCreds := hubCreds
	if masterID != hub {
		mgmtCreds, err = assumeRole(ctx, conn, base, masterID, role, "clawpatrol-orgresolve")
		if err != nil {
			return nil, err
		}
	}
	names, err := listAccountNames(ctx, conn, mgmtCreds)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	return names, nil
}

func callerAccount(ctx context.Context, conn *pluginsdk.Conn, creds aws.Credentials) (string, error) {
	out, err := sts.NewFromConfig(awsConfig(conn, creds)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

func describeOrgMaster(ctx context.Context, conn *pluginsdk.Conn, creds aws.Credentials) (string, error) {
	out, err := organizations.NewFromConfig(awsConfig(conn, creds)).DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return "", err
	}
	if out.Organization == nil {
		return "", fmt.Errorf("describe organization: empty response")
	}
	return aws.ToString(out.Organization.MasterAccountId), nil
}

func listAccountNames(ctx context.Context, conn *pluginsdk.Conn, creds aws.Credentials) (map[string]string, error) {
	client := organizations.NewFromConfig(awsConfig(conn, creds))
	names := map[string]string{}
	var token *string
	for {
		out, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, a := range out.Accounts {
			names[aws.ToString(a.Id)] = aws.ToString(a.Name)
		}
		if out.NextToken == nil {
			return names, nil
		}
		token = out.NextToken
	}
}

// awsConfig builds an SDK config that signs with creds in the STS/global
// region and reaches AWS only through the gateway's brokered dial.
func awsConfig(conn *pluginsdk.Conn, creds aws.Credentials) aws.Config {
	return aws.Config{
		Region:      stsRegion,
		Credentials: awscreds.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		HTTPClient:  brokeredHTTPClient(conn),
	}
}
