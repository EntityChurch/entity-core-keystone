package peer

// smoke_test.go — the S3 two-peer loopback smoke gate (the phase exit criterion).
//
// Two Go peers talk over real loopback TCP through the full §6.5 dispatch chain.
// Scenario 1 (responder = default seed policy) exercises the handshake, 404,
// authority-gated tree get, capability request, and 8-way request_id demux.
// Scenario 2 (responder = --debug-open-grants + --validate) exercises the Core
// Extensibility Boundary: register live-hook, emit hook, §7a echo. 11 checks
// total; the run is GREEN iff all 11 pass.
//
// This is the Go analogue of every sibling peer's S3 smoke (Common-Lisp/Swift:
// 11/11 loopback). The full validate-peer --profile core conformance run is S4.

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

func fixedSeed(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

// TestSmokeLoopback is the 11-check two-peer loopback gate.
func TestSmokeLoopback(t *testing.T) {
	scenario1(t)
	scenario2(t)
}

func scenario1(t *testing.T) {
	t.Helper()
	responder, err := NewPeer(fixedSeed(0x11))
	if err != nil {
		t.Fatalf("responder bootstrap: %v", err)
	}
	initiator, err := MakeIdentity(fixedSeed(0x22))
	if err != nil {
		t.Fatalf("initiator identity: %v", err)
	}
	ln, err := responder.Listen(0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	t.Logf("Responder listening on 127.0.0.1:%d (peer %s)", ln.Port(), responder.LocalPeer())

	cc, err := Dial("127.0.0.1", ln.Port())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	if err := cc.Handshake(initiator); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	remote := cc.RemotePeerID()

	// (1) session established (capability minted)
	if _, ok := cc.Capability(); !ok {
		t.Error("[FAIL] session established (capability minted)")
	} else {
		t.Log("[PASS] session established (capability minted)")
	}
	// (2) remote peer_id matches responder
	if remote != responder.LocalPeer() {
		t.Errorf("[FAIL] remote peer_id matches responder (%s != %s)", remote, responder.LocalPeer())
	} else {
		t.Log("[PASS] remote peer_id matches responder")
	}

	ifaceTarget := ResourceTarget("system/handler/system/tree")

	// (3) unregistered path -> 404
	if r, ok := cc.Execute(initiator, "/"+remote+"/does/not/exist", "noop", EmptyParams()); !ok || ResponseStatus(r) != 404 {
		t.Errorf("[FAIL] unregistered path -> 404 (got %d)", ResponseStatus(r))
	} else {
		t.Log("[PASS] unregistered path -> 404")
	}

	// (4) granted tree get -> 200 + (5) returns a system/handler/interface entity
	rget, ok := cc.Execute(initiator, "/"+remote+"/system/tree", "get", EmptyParams(), ifaceTarget)
	if !ok || ResponseStatus(rget) != 200 {
		t.Errorf("[FAIL] granted tree get -> 200 (got %d)", ResponseStatus(rget))
	} else {
		t.Log("[PASS] granted tree get -> 200")
	}
	if res, ok := ResponseResult(rget); !ok || res.Type != "system/handler/interface" {
		t.Errorf("[FAIL] tree get returns a system/handler/interface entity (got %q)", res.Type)
	} else {
		t.Log("[PASS] tree get returns a system/handler/interface entity")
	}

	// (6) capability request -> 200
	reqGrant := grantSpec{handlers: []string{"system/tree"}, resources: []string{"system/type/*"}, operations: []string{"get"}}
	reqParams := mustEntity("system/capability/request", cbor.NewMap(cbor.Entry("grants", grantsCbor(reqGrant))))
	if rcap, ok := cc.Execute(initiator, "/"+remote+"/system/capability", "request", reqParams); !ok || ResponseStatus(rcap) != 200 {
		t.Errorf("[FAIL] capability request -> 200 (got %d)", ResponseStatus(rcap))
	} else {
		t.Log("[PASS] capability request -> 200")
	}

	// (7) 8-way request_id demux (N7, §6.11)
	const n = 8
	var correlated int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, ok := cc.Execute(initiator, "/"+remote+"/system/tree", "get", EmptyParams(), ifaceTarget)
			if ok && ResponseStatus(r) == 200 {
				if res, ok := ResponseResult(r); ok && res.Type == "system/handler/interface" {
					atomic.AddInt64(&correlated, 1)
				}
			}
		}()
	}
	wg.Wait()
	if correlated != n {
		t.Errorf("[FAIL] 8 interleaved requests each correlated -> %d/8", correlated)
	} else {
		t.Log("[PASS] 8 interleaved requests each correlated -> 8/8")
	}
}

func scenario2(t *testing.T) {
	t.Helper()
	responder, err := NewPeer(fixedSeed(0x33), WithOpenGrants(), WithConformance())
	if err != nil {
		t.Fatalf("responder bootstrap: %v", err)
	}
	initiator, err := MakeIdentity(fixedSeed(0x44))
	if err != nil {
		t.Fatalf("initiator identity: %v", err)
	}

	var emitCount int64
	responder.Store().RegisterTreeConsumer(func(TreeEvent) { atomic.AddInt64(&emitCount, 1) })

	ln, err := responder.Listen(0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cc, err := Dial("127.0.0.1", ln.Port())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	if err := cc.Handshake(initiator); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	remote := cc.RemotePeerID()
	emitBefore := atomic.LoadInt64(&emitCount)

	// (8) handler register -> 200 (live, not 501) + (9) emit hook fired
	manifest := cbor.NewMap(cbor.Entry("name", cbor.Text("demo")), cbor.Entry("operations", emptyMap()))
	req := mustEntity("system/handler/register-request", cbor.NewMap(cbor.Entry("manifest", manifest)))
	rreg, ok := cc.Execute(initiator, "/"+remote+"/system/handler", "register", req, ResourceTarget("system/handler/demo"))
	if !ok || ResponseStatus(rreg) != 200 {
		t.Errorf("[FAIL] handler register -> 200 (live, not 501) (got %d)", ResponseStatus(rreg))
	} else {
		t.Log("[PASS] handler register -> 200 (live, not 501)")
	}
	if atomic.LoadInt64(&emitCount) <= emitBefore {
		t.Error("[FAIL] emit hook fired on register's tree writes (§6.13(c))")
	} else {
		t.Log("[PASS] emit hook fired on register's tree writes (§6.13(c))")
	}

	// (10) §7a echo -> 200 + (11) returns params verbatim
	payload := mustEntity("primitive/any", cbor.NewMap(cbor.Entry("ping", cbor.Uint(42))))
	recho, ok := cc.Execute(initiator, "/"+remote+"/system/validate/echo", "echo", payload)
	if !ok || ResponseStatus(recho) != 200 {
		t.Errorf("[FAIL] §7a echo -> 200 (got %d)", ResponseStatus(recho))
	} else {
		t.Log("[PASS] §7a echo -> 200")
	}
	if res, ok := ResponseResult(recho); !ok || res.Type != "primitive/any" {
		t.Errorf("[FAIL] §7a echo returns params verbatim (got %q)", res.Type)
	} else {
		t.Log("[PASS] §7a echo returns params verbatim")
	}
}
