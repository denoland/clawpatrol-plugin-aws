package main

import (
	"fmt"
	"net/http"
	"strings"
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

// decodeAWSChunkedNoPanic calls decodeAWSChunked and reports a panic as a test
// failure, so a size bound that lets an out-of-range slice expression through
// shows up as a failing case instead of taking the test binary down with it.
func decodeAWSChunkedNoPanic(t *testing.T, body string) (out []byte, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("decodeAWSChunked(%q) panicked: %v", body, r)
			out, err = nil, fmt.Errorf("panicked: %v", r)
		}
	}()
	return decodeAWSChunked([]byte(body))
}

// TestDecodeAWSChunkedSizeBounds pins the chunk-size bound. The size field is
// written by the agent, so every value an int64 can hold reaches it, and the
// bound has to hold for all of them without arithmetic of its own overflowing.
func TestDecodeAWSChunkedSizeBounds(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		want   string // decoded content, when errSub is empty
		errSub string // substring the error has to contain
	}{
		{
			// math.MaxInt64: adding this to any non-zero read offset wraps
			// to a negative value that is below every length.
			name:   "size at MaxInt64",
			body:   "7fffffffffffffff\r\nhi\r\n0\r\n\r\n",
			errSub: "exceeds remaining body",
		},
		{
			// Same size with the read offset already at the end of the
			// body, so the remaining count is exactly zero.
			name:   "size at MaxInt64 with nothing left",
			body:   "7fffffffffffffff\r\n",
			errSub: "exceeds remaining body",
		},
		{
			// math.MaxUint64 does not fit an int64 and never becomes a size.
			name:   "size past MaxInt64",
			body:   "ffffffffffffffff\r\nhi\r\n0\r\n\r\n",
			errSub: "bad chunk size",
		},
		{
			name:   "negative size field",
			body:   "-1\r\nhi\r\n0\r\n\r\n",
			errSub: "negative chunk size",
		},
		{
			name:   "non-hex size field",
			body:   "zz\r\nhi\r\n0\r\n\r\n",
			errSub: "bad chunk size",
		},
		{
			// A size equal to the bytes that remain clears the bound; the
			// body then ends with no terminating zero chunk, so the failure
			// names the missing header rather than the size.
			name:   "size exactly the bytes that remain",
			body:   "4\r\nabcd",
			errSub: "no CRLF",
		},
		{
			name:   "size one byte over the bytes that remain",
			body:   "5\r\nabcd",
			errSub: "exceeds remaining body",
		},
		{
			name: "zero size terminates",
			body: "0\r\n\r\n",
			want: "",
		},
		{
			name: "size equal to the data before the terminator",
			body: "4\r\nabcd\r\n0\r\n\r\n",
			want: "abcd",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeAWSChunkedNoPanic(t, c.body)
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Fatalf("decode = (%q, %v), want an error containing %q", got, err, c.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("decode = %q, want %q", got, c.want)
			}
		})
	}
}
