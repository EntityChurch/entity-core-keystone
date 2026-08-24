package peer

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// RT-13b §4.1 Class R — a >=2-writer test asserting FRAME-BOUNDARY INTEGRITY of
// the emitted stream, not demux timing (research/diagnostics/
// rt13-write-concurrency-classes.md). The gap this closes: the ground-up Go
// peer's own connection_multiplex_test.go exercises the write path but asserts
// response routing, not that concurrent writers never interleave two frames'
// bytes on the wire — a property writeLock (transport.go) is supposed to
// guarantee and which this test would catch a regression in.
//
// Run under the race detector: `go test -race -run TestConcurrentWritersFrameBoundaryIntegrity ./peer/...`
func TestConcurrentWritersFrameBoundaryIntegrity(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	io := newTransportIO(clientConn)

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			requestID := fmt.Sprintf("rq-%04d", i)
			env := NewEnvelope(MakeResponse(requestID, uint64(i), EmptyParams()))
			if err := io.writeFramed(env); err != nil {
				t.Errorf("writeFramed(%d): %v", i, err)
			}
		}(i)
	}

	// Single reader, sequential — the read side does not need its own lock
	// (nothing else reads serverConn), but every frame it decodes must be
	// EXACTLY what one writer sent: a torn/interleaved write would either fail
	// to decode as CBOR or decode into a request_id/status pair that no writer
	// ever produced together (evidence of byte-splicing across two frames).
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		payload, err := ReadFrame(serverConn)
		if err != nil {
			t.Fatalf("ReadFrame(%d): %v", i, err)
		}
		env, err := EnvelopeOfFrame(payload)
		if err != nil {
			t.Fatalf("frame %d failed to decode as a well-formed envelope (byte-spliced across concurrent writers?): %v", i, err)
		}
		requestID, ok := env.Root.Text("request_id")
		if !ok {
			t.Fatalf("frame %d decoded but has no request_id field (corrupted envelope)", i)
		}
		status, ok := env.Root.Uint("status")
		if !ok {
			t.Fatalf("frame %d (request_id=%s) decoded but has no status field (corrupted envelope)", i, requestID)
		}
		var wantIdx int
		if _, err := fmt.Sscanf(requestID, "rq-%04d", &wantIdx); err != nil {
			t.Fatalf("frame %d: unparseable request_id %q (bytes from a different frame spliced in?)", i, requestID)
		}
		if uint64(wantIdx) != status {
			t.Fatalf("frame %d: request_id %q paired with status=%d, want %d — this is exactly the corruption shape a torn concurrent write produces (one frame's header/id with another's body)", i, requestID, status, wantIdx)
		}
		if seen[requestID] {
			t.Fatalf("request_id %q delivered twice — a write was duplicated or a frame boundary was misread", requestID)
		}
		seen[requestID] = true
	}

	wg.Wait()
	if len(seen) != n {
		t.Fatalf("got %d distinct frames, want %d", len(seen), n)
	}
}
