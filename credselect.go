package main

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/denoland/clawpatrol/pluginsdk"
)

// selectBaseKey returns the base AWS credentials used to assume the target
// account's role. The endpoint may bind more than one aws_account credential,
// each tagged with the accounts its key serves; selectBaseKey picks the one
// whose `accounts` list contains accountID, falling back to a bound credential
// that lists no accounts (the catch-all). With a single bound credential — the
// common case — that one is used for every account.
//
// On a gateway too old to deliver the credential set (conn.Credentials nil) it
// falls back to the single credential carried in the legacy singular fields.
func selectBaseKey(conn *pluginsdk.Conn, accountID string) (aws.Credentials, error) {
	if len(conn.Credentials) == 0 {
		return baseKey(conn), nil // legacy single-credential delivery
	}
	var fallback *pluginsdk.ConnCredential
	for i := range conn.Credentials {
		c := &conn.Credentials[i]
		if c.TypeName != "aws_account" {
			continue
		}
		accts := credentialAccounts(c.CanonicalConfig)
		if len(accts) == 0 {
			if fallback == nil {
				fallback = c
			}
			continue
		}
		for _, a := range accts {
			if a == accountID {
				return credFromExtras(c.Extras), nil
			}
		}
	}
	if fallback != nil {
		return credFromExtras(fallback.Extras), nil
	}
	return aws.Credentials{}, fmt.Errorf(
		"no aws_account credential serves account %s (tag a credential's accounts with it, or bind a credential with no accounts as the fallback)", accountID)
}

func credFromExtras(ex map[string]string) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     ex["access_key_id"],
		SecretAccessKey: ex["secret_access_key"],
		SessionToken:    ex["session_token"],
	}
}

// credentialAccounts decodes the `accounts` list from an aws_account
// credential's canonical config, or nil when absent/empty.
func credentialAccounts(canonical []byte) []string {
	if len(canonical) == 0 {
		return nil
	}
	var cfg struct {
		Accounts []string `json:"accounts"`
	}
	_ = json.Unmarshal(canonical, &cfg)
	return cfg.Accounts
}
