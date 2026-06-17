package main

import (
	"testing"

	"github.com/denoland/clawpatrol/pluginsdk"
)

func TestSelectBaseKey(t *testing.T) {
	cred := func(inst string, accounts string, key string) pluginsdk.ConnCredential {
		canon := []byte("{}")
		if accounts != "" {
			canon = []byte(`{"accounts":[` + accounts + `]}`)
		}
		return pluginsdk.ConnCredential{
			TypeName:        "aws_account",
			Instance:        inst,
			Extras:          map[string]string{"access_key_id": key, "secret_access_key": "s"},
			CanonicalConfig: canon,
		}
	}

	t.Run("legacy single-credential fields", func(t *testing.T) {
		conn := &pluginsdk.Conn{CredentialExtras: map[string]string{"access_key_id": "AKIA_LEGACY", "secret_access_key": "s"}}
		got, err := selectBaseKey(conn, "111111111111")
		if err != nil || got.AccessKeyID != "AKIA_LEGACY" {
			t.Fatalf("legacy = %q, %v", got.AccessKeyID, err)
		}
	})

	t.Run("single untagged credential serves any account", func(t *testing.T) {
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{cred("base", "", "AKIA_ALL")}}
		got, err := selectBaseKey(conn, "999999999999")
		if err != nil || got.AccessKeyID != "AKIA_ALL" {
			t.Fatalf("untagged = %q, %v", got.AccessKeyID, err)
		}
	})

	t.Run("tagged credential matches its account", func(t *testing.T) {
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{
			cred("prod", `"111111111111","222222222222"`, "AKIA_PROD"),
			cred("fallback", "", "AKIA_FALLBACK"),
		}}
		got, err := selectBaseKey(conn, "222222222222")
		if err != nil || got.AccessKeyID != "AKIA_PROD" {
			t.Fatalf("tagged = %q, %v", got.AccessKeyID, err)
		}
	})

	t.Run("unclaimed account uses fallback", func(t *testing.T) {
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{
			cred("prod", `"111111111111"`, "AKIA_PROD"),
			cred("fallback", "", "AKIA_FALLBACK"),
		}}
		got, err := selectBaseKey(conn, "333333333333")
		if err != nil || got.AccessKeyID != "AKIA_FALLBACK" {
			t.Fatalf("fallback = %q, %v", got.AccessKeyID, err)
		}
	})

	t.Run("no match and no fallback errors", func(t *testing.T) {
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{
			cred("prod", `"111111111111"`, "AKIA_PROD"),
		}}
		if _, err := selectBaseKey(conn, "333333333333"); err == nil {
			t.Fatal("want error when no credential serves the account and there is no fallback")
		}
	})

	t.Run("non-aws_account credential is skipped", func(t *testing.T) {
		other := pluginsdk.ConnCredential{TypeName: "bearer_token", Instance: "x", Extras: map[string]string{"access_key_id": "NOPE", "secret_access_key": "s"}}
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{other, cred("base", "", "AKIA_ALL")}}
		got, err := selectBaseKey(conn, "111111111111")
		if err != nil || got.AccessKeyID != "AKIA_ALL" {
			t.Fatalf("got %q, %v; non-aws_account should be skipped", got.AccessKeyID, err)
		}
	})

	t.Run("malformed canonical falls through to fallback", func(t *testing.T) {
		bad := pluginsdk.ConnCredential{TypeName: "aws_account", Instance: "bad", CanonicalConfig: []byte("{not json"), Extras: map[string]string{"access_key_id": "AKIA_BAD", "secret_access_key": "s"}}
		conn := &pluginsdk.Conn{Credentials: []pluginsdk.ConnCredential{bad}}
		// Malformed canonical -> no accounts -> treated as the fallback.
		got, err := selectBaseKey(conn, "111111111111")
		if err != nil || got.AccessKeyID != "AKIA_BAD" {
			t.Fatalf("got %q, %v; malformed canonical should be treated as fallback", got.AccessKeyID, err)
		}
	})
}
