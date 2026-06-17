package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// isAWSChunked reports whether the request body is in aws-chunked
// content-encoding (S3 streaming uploads). Detected by the
// Content-Encoding token or the STREAMING-* x-amz-content-sha256 marker.
func isAWSChunked(h http.Header) bool {
	if containsToken(h.Get("Content-Encoding"), "aws-chunked") {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(h.Get("X-Amz-Content-Sha256")), "STREAMING-")
}

// headerKeys returns a snapshot of the header names, so callers can delete
// entries while iterating without mutating the map during range.
func headerKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	return keys
}

func containsToken(headerValue, token string) bool {
	for _, part := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// decodeAWSChunked decodes an aws-chunked request body into its raw
// content. The wire format is a sequence of
//
//	<hex-size>[;chunk-signature=<hex>][;...]\r\n<size bytes>\r\n
//
// chunks, terminated by a zero-size chunk that may be followed by trailing
// headers (the unsigned-trailer checksum variant). Per-chunk signatures and
// trailers are ignored — only the data bytes are needed, since the gateway
// re-signs the reconstructed payload from scratch.
func decodeAWSChunked(body []byte) ([]byte, error) {
	out := make([]byte, 0, len(body))
	i := 0
	for {
		j := bytes.Index(body[i:], []byte("\r\n"))
		if j < 0 {
			return nil, fmt.Errorf("malformed chunk header (no CRLF)")
		}
		line := body[i : i+j]
		i += j + 2

		sizeField := line
		if k := bytes.IndexByte(line, ';'); k >= 0 {
			sizeField = line[:k]
		}
		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeField)), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad chunk size %q: %w", string(bytes.TrimSpace(sizeField)), err)
		}
		if size < 0 {
			return nil, fmt.Errorf("negative chunk size %d", size)
		}
		if size == 0 {
			// Final chunk; any trailers that follow are not part of the
			// object content.
			break
		}
		if int64(i)+size > int64(len(body)) {
			return nil, fmt.Errorf("chunk size %d exceeds remaining body %d", size, len(body)-i)
		}
		out = append(out, body[i:i+int(size)]...)
		i += int(size)
		// Optional trailing CRLF after the chunk data.
		if i+2 <= len(body) && body[i] == '\r' && body[i+1] == '\n' {
			i += 2
		}
	}
	return out, nil
}
