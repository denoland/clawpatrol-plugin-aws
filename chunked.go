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
//
// The chunk sizes are written by the agent, so every value an int64 can hold
// reaches the scan. The read offset i therefore holds to [0, len(body)]
// throughout, and every bound on it counts the bytes that remain by
// subtracting i from len(body) rather than by adding to i: a sum involving a
// size near math.MaxInt64 wraps negative, lands below every length, and
// clears an additive bound on its way to an out-of-range slice.
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
		// ParseInt honors a sign prefix in base 16 too, so the size field
		// can name a negative value. It is rejected here because the bound
		// below, and the slice expression under it, both require a
		// non-negative size: a negative one clears the bound and slices
		// backwards.
		if size < 0 {
			return nil, fmt.Errorf("negative chunk size %d", size)
		}
		if size == 0 {
			// Final chunk; any trailers that follow are not part of the
			// object content.
			break
		}
		// Clearing this bound is what makes int(size) exact and keeps both
		// i+int(size) and the slice below within len(body).
		if size > int64(len(body)-i) {
			return nil, fmt.Errorf("chunk size %d exceeds remaining body %d", size, len(body)-i)
		}
		out = append(out, body[i:i+int(size)]...)
		i += int(size)
		// Optional trailing CRLF after the chunk data. Two bytes have to
		// remain for body[i] and body[i+1] to be in range.
		if len(body)-i >= 2 && body[i] == '\r' && body[i+1] == '\n' {
			i += 2
		}
	}
	return out, nil
}
