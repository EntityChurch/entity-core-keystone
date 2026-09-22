package peer

// pd2_outbound_gate_test.go — §1.4 PD-2: the outbound sub-dispatch gate.
//
// WHY THESE CASES AND NOT THE TWO OBVIOUS ONES. §1.4 says outright that a check
// set MUST discriminate a COMPOSE from a BYPASS, and that the two obvious vectors
// — both sources agree -> allow, no source at all -> refuse — are exactly the two
// that pass a peer whose credential path bypasses the handler's grant. So the
// load-bearing case here is `PresentedCredentialOutOfHandlerGrant`: a VALID
// target-minted credential presented for an operation the handler's own grant
// does NOT cover, which MUST refuse. It is the only case that fails on a peer
// with the bypass and passes on one without.
//
// The grant-path case is a regression control for a real defect: ctx.pattern
// arrives ABSOLUTE from §6.6's walk and the grant path wants it peer-relative, so
// the naive concatenation misses and the handler fails closed with 403 on a peer
// whose grant is correct. That 403 is indistinguishable at the wire from an
// authority verdict, which is why it gets a test rather than a comment.

import (
	"testing"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// mintReentryCred mints, at `target`, a credential naming `grantee` and covering
// `ops` on `handlers`. It returns the credential plus the entities a verifier
// needs in `included` to resolve it: the target's peer entity and the link
// signature.
func mintReentryCred(t *testing.T, target *Peer, granteeHash []byte, handlers, ops []string) (Entity, []Entity) {
	t.Helper()
	grants := grantsCbor(grantSpec{
		handlers:   handlers,
		operations: ops,
		resources:  []string{"*"},
	})
	cred, sig := target.mintToken(granteeHash, grants, nil, nil)
	return cred, []Entity{target.identity.PeerEntity(), sig}
}

func twoPeers(t *testing.T) (local, remote *Peer) {
	t.Helper()
	ls := make([]byte, 32)
	ls[0] = 1
	rs := make([]byte, 32)
	rs[0] = 2
	var err error
	if local, err = NewPeer(ls, WithConformance()); err != nil {
		t.Fatal(err)
	}
	if remote, err = NewPeer(rs, WithConformance()); err != nil {
		t.Fatal(err)
	}
	return local, remote
}

func TestPD2GrantPathResolvesFromEitherPatternForm(t *testing.T) {
	p, err := NewPeer(make([]byte, 32), WithConformance())
	if err != nil {
		t.Fatal(err)
	}
	rel := "system/validate/dispatch-outbound"
	abs, ok := p.resolveHandler("/" + p.localPeer + "/" + rel)
	if !ok {
		t.Fatalf("handler did not resolve")
	}
	if abs == rel {
		t.Fatalf("precondition gone: resolveHandler no longer answers an absolute pattern (%q) — "+
			"this test exists because it does, and the grant path wants the relative form", abs)
	}
	for _, form := range []string{rel, abs} {
		if _, found := p.store.GetAt(grantPathFor(p.localPeer, form)); !found {
			t.Errorf("own grant not found from pattern form %q", form)
		}
	}
}

func TestPD2HandlerGrantIsNarrow(t *testing.T) {
	p, err := NewPeer(make([]byte, 32), WithConformance())
	if err != nil {
		t.Fatal(err)
	}
	g, ok := p.store.GetAt(grantPathFor(p.localPeer, "system/validate/dispatch-outbound"))
	if !ok {
		t.Fatal("no own grant")
	}
	// A WIDE grant here would make every case below pass for the wrong reason:
	// consulting the grant and skipping it would agree on every input, so the
	// compose/bypass discriminator could not fire at all.
	recs := grantsOfToken(g)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 grant, got %d", len(recs))
	}
	for _, s := range [][]string{recs[0].handlers.incl, recs[0].operations.incl, recs[0].resources.incl} {
		for _, v := range s {
			if v == "*" {
				t.Fatalf("dispatch-outbound own grant contains a wildcard (%v) — "+
					"a wide grant makes the §6.8 discriminator vacuous", recs[0])
			}
		}
	}
}

func TestPD2OutboundGate(t *testing.T) {
	local, remote := twoPeers(t)
	ownGrant, ok := local.store.GetAt(grantPathFor(local.localPeer, "system/validate/dispatch-outbound"))
	if !ok {
		t.Fatal("no own grant")
	}
	echoTarget := "system/validate/echo"
	resource := ResourceTarget("system/handler/" + echoTarget)

	// A valid credential minted BY the remote (the reentry target) naming the
	// local peer as grantee, covering echo.
	credEcho, incEcho := mintReentryCred(t, remote, local.identity.IdentityHash(),
		[]string{echoTarget}, []string{"echo"})
	// The same, but covering a DIFFERENT operation: this is the credential whose
	// scope is wide enough on its own and which the handler grant must still gate.
	credWide, incWide := mintReentryCred(t, remote, local.identity.IdentityHash(),
		[]string{"*"}, []string{"*"})

	mk := func(es []Entity) Included {
		in := make(Included, len(es))
		for _, e := range es {
			in.Add(e)
		}
		return in
	}

	cases := []struct {
		name      string
		operation string
		cred      Entity
		hasCred   bool
		inc       Included
		want      bool
		why       string
	}{
		{
			name: "PresentedCredentialInHandlerGrant", operation: "echo",
			cred: credEcho, hasCred: true, inc: mk(incEcho), want: true,
			why: "the compose: handler grant covers echo, credential relaxes Dimension 4 to the target",
		},
		{
			name: "PresentedCredentialOutOfHandlerGrant", operation: "reentry-oos-probe",
			cred: credWide, hasCred: true, inc: mk(incWide), want: false,
			why: "THE discriminating vector (§1.4): a valid target-minted credential for an " +
				"operation the handler's OWN grant does not cover MUST refuse. A peer that " +
				"treats the credential as a standalone authorizer allows this",
		},
		{
			name: "AmbientNoCredential", operation: "echo",
			cred: Entity{}, hasCred: false, inc: mk(nil), want: false,
			why: "the ambient arm: Dimension 4 is decided by the handler grant alone, whose " +
				"absent peers scope defaults to {include:[local]}, so a foreign target fails",
		},
		{
			name: "CredentialPresentButUnresolvable", operation: "echo",
			cred: credEcho, hasCred: true, inc: mk(nil), want: false,
			why: "a credential that fails verification relaxes NOTHING and the handler grant " +
				"gates unrelaxed — it does not become an error and it does not become a pass",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkOutboundSubDispatch(local.localPeer, remote.localPeer, echoTarget, tc.operation,
				local.store, ownGrant, resource, tc.cred, tc.hasCred, tc.inc)
			if got != tc.want {
				t.Errorf("checkOutboundSubDispatch = %v, want %v\nwhy: %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestPD2MultisigRootNeverRelaxesDimension4 is E3/F66. A K-of-N root is a GROUP's
// authority, so it is not "minted BY the target peer" and never relaxes Dimension
// 4 (§1.4, 0.8.2.19) — even when the quorum itself is well-formed and would verify
// locally. Accepting it would let any one signer's target confer the whole group's
// grant.
func TestPD2MultisigRootNeverRelaxesDimension4(t *testing.T) {
	local, remote := twoPeers(t)
	ownGrant, _ := local.store.GetAt(grantPathFor(local.localPeer, "system/validate/dispatch-outbound"))
	echoTarget := "system/validate/echo"
	resource := ResourceTarget("system/handler/" + echoTarget)

	// The control: the SAME request with a single-signature root from the same
	// target must be ALLOWED. Without it, a peer that refuses every credential
	// form passes this test for a reason that has nothing to do with §1.4 —
	// fail-closed by absence, which GUIDE-CONFORMANCE §2.4b names.
	credSingle, incSingle := mintReentryCred(t, remote, local.identity.IdentityHash(),
		[]string{echoTarget}, []string{"echo"})
	inSingle := make(Included)
	for _, e := range incSingle {
		inSingle.Add(e)
	}
	if !checkOutboundSubDispatch(local.localPeer, remote.localPeer, echoTarget, "echo",
		local.store, ownGrant, resource, credSingle, true, inSingle) {
		t.Fatal("single-signature control was refused — the multi-sig arm below would then " +
			"pass for an unrelated reason and measure nothing")
	}

	// The variable is the GRANTER FORM and nothing else: same operation, same
	// target, same scope, same grantee.
	//
	// ⚠ THE QUORUM MUST BE ONE THAT WOULD OTHERWISE VERIFY, AND THE LOCAL PEER
	// MUST BE IN IT. This is the whole discriminating power of the case and the
	// first version of this test did not have it: with signers {remote, other},
	// §5.5's M6 (the local peer MUST be a quorum member) refuses the root for a
	// reason that has nothing to do with §1.4, so the case went green with the
	// foreign-frame guard PLANTED OUT — an inert control that reads exactly like a
	// passing one. Signers {local, remote} at threshold 2, both signing, satisfies
	// M3, M4 and M6, so the ONLY thing that can refuse it is the rule under test.
	grants := grantsCbor(grantSpec{
		handlers:   []string{echoTarget},
		operations: []string{"echo"},
		resources:  []string{"*"},
	})
	credMulti := mustEntity("system/capability/token", cbor.NewMap(
		cbor.Entry("granter", cbor.NewMap(
			cbor.Entry("signers", msArray(
				cbor.Bytes(local.identity.IdentityHash()),
				cbor.Bytes(remote.identity.IdentityHash()),
			)),
			cbor.Entry("threshold", cbor.Uint(2)),
		)),
		cbor.Entry("grantee", cbor.Bytes(local.identity.IdentityHash())),
		cbor.Entry("grants", grants),
		cbor.Entry("created_at", cbor.Uint(nowMillis())),
	))
	inMulti := make(Included)
	inMulti.Add(local.identity.PeerEntity())
	inMulti.Add(remote.identity.PeerEntity())
	inMulti.Add(local.identity.SignEntity(credMulti))
	inMulti.Add(remote.identity.SignEntity(credMulti))

	// Antecedent control: the quorum is well-formed and DOES verify in the local
	// frame. If this fails, the case below refuses for a structural reason and
	// measures nothing — which is exactly the state the first version was in.
	if verifyCapabilityChainRootedAt(local.localPeer, local.localPeer, local.store, credMulti, inMulti) != VerdictAllow {
		t.Fatal("the quorum does not verify even locally — this case cannot discriminate the " +
			"foreign-frame rule from an ordinary M3/M4/M6 refusal")
	}

	if checkOutboundSubDispatch(local.localPeer, remote.localPeer, echoTarget, "echo",
		local.store, ownGrant, resource, credMulti, true, inMulti) {
		t.Error("a K-of-2 multi-signature root relaxed Dimension 4 — §1.4: a multi-signature " +
			"root NEVER relaxes it, because *minted by the target* means the target SOLELY " +
			"minted it and a quorum is the group's authority")
	}
}

// TestPeerRelativeOfAllThreeSpellings pins §1.4's three spellings of one address
// onto the one form a grant can match.
//
// The validator sends the SCHEMED ABSOLUTE form, and this transform is what the
// first cut of the PD-2 gate was missing: the gate was handed
// `entity://{peer}/system/validate/echo` as a handler pattern, matched no grant,
// and refused the legitimate reentry with 403 — an authority-shaped answer to a
// path bug. The last case is the standing defect from `smalltalk` and `forth`: an
// UNCONDITIONAL first-segment strip turns `system/protocol/connect` into
// `protocol/connect`, which made every self-minted grant unusable while the
// handshake stayed green.
func TestPeerRelativeOfAllThreeSpellings(t *testing.T) {
	local := "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"
	remote := "2K8mc32Lv3cJdniUfdAVv69DkqHqTzwq6GyHtroBX6ogUF"
	if !isPeerID(remote) || !isPeerID(local) {
		t.Fatalf("precondition: the fixtures must be peer_ids or the strip arm is never taken")
	}
	cases := []struct{ in, want, why string }{
		{"system/validate/echo", "system/validate/echo", "peer-relative: unchanged"},
		{"/" + remote + "/system/validate/echo", "system/validate/echo", "absolute: peer segment dropped"},
		{"entity://" + remote + "/system/validate/echo", "system/validate/echo", "schemed: what the validator sends"},
		{"entity://" + local + "/system/validate/echo", "system/validate/echo", "own namespace: same transform"},
		{"system/protocol/connect", "system/protocol/connect",
			"⛔ `system` is NOT a peer_id and MUST survive — an unconditional strip is the smalltalk/forth defect"},
		{"/system/protocol/connect", "system/protocol/connect",
			"absolute-looking but the first segment is not a peer_id: only the leading slash goes"},
	}
	for _, tc := range cases {
		if got := peerRelativeOf(local, tc.in); got != tc.want {
			t.Errorf("peerRelativeOf(%q) = %q, want %q\nwhy: %s", tc.in, got, tc.want, tc.why)
		}
	}
}
