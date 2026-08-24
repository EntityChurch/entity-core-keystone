package peer

import (
	"testing"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// §3.6 / §5.5 K-of-N multi-signature ACCEPT-path unit checks.
//
// The Go validate-peer oracle's `multisig` category is dominated by malformed→403
// REJECT probes, which a fail-closed peer passes VACUOUSLY (it rejects
// everything). Its one accept probe (valid_2of3_peer_signed_accepted) only runs
// when the harness provisions the peer keypair so the validator can co-sign AS
// the peer — before that it SKIPs, which had masked a frame-only implementation
// (the peer rejected every multi-grant cap, including a valid co-signed 2-of-3).
// This test guards the genuine-accept direction unconditionally: a valid quorum
// → VerdictAllow; each broken invariant → VerdictAuthzDeny (M3 structure, M4
// distinct-signer threshold, M6 local ∈ signers).

func msSeed(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func msIdentity(t *testing.T, b byte) Identity {
	t.Helper()
	id, err := MakeIdentity(msSeed(b))
	if err != nil {
		t.Fatalf("MakeIdentity(%#x): %v", b, err)
	}
	return id
}

func msArray(vs ...cbor.Value) cbor.Value { return cbor.Value{Kind: cbor.KindArray, Array: vs} }

// msBuild builds a K-of-N quorum cap co-signed by signBy, plus its included set
// (each signer's + the grantee's peer entity, and one signature per signBy).
func msBuild(t *testing.T, signers []Identity, threshold uint64, grantee Identity, signBy []Identity) (Entity, Included) {
	t.Helper()
	sh := make([]cbor.Value, len(signers))
	for i, s := range signers {
		sh[i] = cbor.Bytes(s.IdentityHash())
	}
	capEnt, err := MakeEntity("system/capability/token", cbor.NewMap(
		cbor.Entry("granter", cbor.NewMap(
			cbor.Entry("signers", msArray(sh...)),
			cbor.Entry("threshold", cbor.Uint(threshold)),
		)),
		cbor.Entry("grantee", cbor.Bytes(grantee.IdentityHash())),
	))
	if err != nil {
		t.Fatalf("MakeEntity: %v", err)
	}
	inc := make(Included)
	for _, s := range signers {
		inc.Add(s.PeerEntity())
	}
	inc.Add(grantee.PeerEntity())
	for _, s := range signBy {
		inc.Add(s.SignEntity(capEnt))
	}
	return capEnt, inc
}

func TestMultisigAcceptPath(t *testing.T) {
	a := msIdentity(t, 0x11) // local peer
	b := msIdentity(t, 0x22)
	c := msIdentity(t, 0x33)
	d := msIdentity(t, 0x55)
	grantee := msIdentity(t, 0x44)
	local := a.PeerID()
	store := NewStore()

	cases := []struct {
		name    string
		signers []Identity
		thr     uint64
		signBy  []Identity
		want    Verdict
	}{
		{"valid_2of3_peer_signed_accepted", []Identity{a, b, c}, 2, []Identity{a, b}, VerdictAllow},
		{"below_threshold_denied", []Identity{a, b, c}, 2, []Identity{a}, VerdictAuthzDeny},
		{"local_not_in_signers_denied", []Identity{b, c, d}, 2, []Identity{b, c}, VerdictAuthzDeny},
		{"duplicate_signers_denied", []Identity{a, b, b}, 2, []Identity{a, b}, VerdictAuthzDeny},
		{"threshold_below_two_denied", []Identity{a, b, c}, 1, []Identity{a, b}, VerdictAuthzDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capEnt, inc := msBuild(t, tc.signers, tc.thr, grantee, tc.signBy)
			if got := verifyCapabilityChain(local, store, capEnt, inc); got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}
