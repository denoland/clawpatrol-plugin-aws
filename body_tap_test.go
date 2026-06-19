package main

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// TestBodyTapWriteNeverBlocksAndCapsPrefix writes far more than the cap and
// confirms the tap (a) never blocks the writer and (b) a reader gets exactly
// the first cap bytes, then EOF.
func TestBodyTapWriteNeverBlocksAndCapsPrefix(t *testing.T) {
	const capN = 64 * 1024
	tap := newBodyTap(capN)

	// Write 4x the cap. No reader is draining; Write must not block.
	payload := bytes.Repeat([]byte("A"), capN*4)
	n, err := tap.Write(payload)
	if err != nil {
		t.Fatalf("Write err = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write n = %d, want %d (must report full length consumed)", n, len(payload))
	}
	tap.close()

	got, err := io.ReadAll(tap.reader())
	if err != nil {
		t.Fatalf("ReadAll err = %v", err)
	}
	if len(got) != capN {
		t.Fatalf("captured %d bytes, want exactly cap %d", len(got), capN)
	}
	if !bytes.Equal(got, payload[:capN]) {
		t.Fatalf("captured bytes are not the first %d of the payload", capN)
	}
}

// TestBodyTapShortBody confirms a body smaller than the cap is captured whole.
func TestBodyTapShortBody(t *testing.T) {
	tap := newBodyTap(64 * 1024)
	want := []byte("a short response body")
	if _, err := tap.Write(want); err != nil {
		t.Fatal(err)
	}
	tap.close()
	got, err := io.ReadAll(tap.reader())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBodyTapConcurrentWriteRead drives the real usage pattern: a TeeReader
// fills the tap while a reader drains it concurrently, mirroring resp.Write
// (agent side) racing the gateway's pull. Run under -race to catch data races.
func TestBodyTapConcurrentWriteRead(t *testing.T) {
	const capN = 64 * 1024
	tap := newBodyTap(capN)

	// Source far larger than the cap. The agent side must always read all of
	// it regardless of the tap.
	src := bytes.Repeat([]byte("0123456789"), capN) // 640 KiB
	teed := io.TeeReader(bytes.NewReader(src), tap)

	var wg sync.WaitGroup
	wg.Add(2)

	// Agent side: drain the TeeReader fully (this is resp.Write reading body).
	var agentGot bytes.Buffer
	go func() {
		defer wg.Done()
		if _, err := io.Copy(&agentGot, teed); err != nil {
			t.Errorf("agent copy err = %v", err)
		}
		// Body fully read -> signal EOF to the tap reader.
		tap.close()
	}()

	// Gateway side: drain the tap reader concurrently.
	var gwGot bytes.Buffer
	go func() {
		defer wg.Done()
		if _, err := io.Copy(&gwGot, tap.reader()); err != nil {
			t.Errorf("gateway copy err = %v", err)
		}
	}()

	wg.Wait()

	// The agent must always get the FULL source, untouched by the tap.
	if !bytes.Equal(agentGot.Bytes(), src) {
		t.Fatalf("agent got %d bytes, want full %d", agentGot.Len(), len(src))
	}
	// The gateway gets at most the cap prefix.
	if gwGot.Len() > capN {
		t.Fatalf("gateway got %d bytes, exceeds cap %d", gwGot.Len(), capN)
	}
	if !bytes.Equal(gwGot.Bytes(), src[:gwGot.Len()]) {
		t.Fatal("gateway bytes are not a prefix of the source")
	}
}

// TestBodyTapGatewayNeverPulls confirms that if the gateway never reads the
// tap reader, the writer side still completes fully (the agent is never
// blocked). This is the "older/slow/stuck gateway" case.
func TestBodyTapGatewayNeverPulls(t *testing.T) {
	const capN = 64 * 1024
	tap := newBodyTap(capN)
	src := bytes.Repeat([]byte("x"), capN*8)

	// Hand the reader to "the gateway" but never read it.
	_ = tap.reader()

	var agentGot bytes.Buffer
	if _, err := io.Copy(&agentGot, io.TeeReader(bytes.NewReader(src), tap)); err != nil {
		t.Fatalf("agent copy err = %v", err)
	}
	tap.close()
	if !bytes.Equal(agentGot.Bytes(), src) {
		t.Fatalf("agent got %d bytes, want full %d", agentGot.Len(), len(src))
	}
}
