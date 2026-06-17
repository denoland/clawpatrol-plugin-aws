package main

import (
	"net/http"
	"testing"
)

func TestIsAWSChunked(t *testing.T) {
	cases := []struct {
		ce, sha string
		want    bool
	}{
		{"aws-chunked", "", true},
		{"aws-chunked, gzip", "", true},
		{"gzip", "", false},
		{"", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true},
		{"", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", true},
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"", "", false},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.ce != "" {
			h.Set("Content-Encoding", c.ce)
		}
		if c.sha != "" {
			h.Set("X-Amz-Content-Sha256", c.sha)
		}
		if got := isAWSChunked(h); got != c.want {
			t.Errorf("isAWSChunked(ce=%q sha=%q) = %v, want %v", c.ce, c.sha, got, c.want)
		}
	}
}

func TestDecodeAWSChunked(t *testing.T) {
	// Signed-chunk form: "<hexsize>;chunk-signature=<sig>\r\n<data>\r\n".
	signed := "b;chunk-signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n" +
		"hello world\r\n" +
		"0;chunk-signature=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\r\n\r\n"
	got, err := decodeAWSChunked([]byte(signed))
	if err != nil {
		t.Fatalf("signed: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("signed decode = %q, want %q", got, "hello world")
	}

	// Multi-chunk.
	multi := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	got, err = decodeAWSChunked([]byte(multi))
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("multi decode = %q, want %q", got, "hello world")
	}

	// Unsigned-trailer form: zero chunk followed by a trailer header.
	trailer := "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:abc123==\r\n\r\n"
	got, err = decodeAWSChunked([]byte(trailer))
	if err != nil {
		t.Fatalf("trailer: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("trailer decode = %q, want %q", got, "hello")
	}

	// Empty object: a single zero chunk.
	got, err = decodeAWSChunked([]byte("0\r\n\r\n"))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty decode = %q, want empty", got)
	}

	// Malformed: missing CRLF.
	if _, err := decodeAWSChunked([]byte("5hello")); err == nil {
		t.Fatal("expected error for malformed body")
	}
	// Malformed: chunk size exceeds body.
	if _, err := decodeAWSChunked([]byte("ff\r\nhi\r\n0\r\n\r\n")); err == nil {
		t.Fatal("expected error for oversized chunk")
	}
}
