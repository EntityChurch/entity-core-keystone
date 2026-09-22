package peer

// bootstrap.go — §6.9 bootstrap: instantiate the MUST handlers, write their tree
// entities, publish the §6.9a peer-authority owner cap + seed-policy default, and
// (under --validate) the §7a conformance handlers.

import (
	"encoding/hex"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

// Option configures peer construction.
type Option func(*Peer)

// WithOpenGrants enables the --debug-open-grants degenerate [default -> *] seed
// (the cohort's explicitly non-conformant debug wildcard; reaches write/grant-
// gated ops past the F27 owner-authority gap).
func WithOpenGrants() Option { return func(p *Peer) { p.openGrants = true } }

// WithConformance enables the §7a system/validate/* conformance handlers
// (off by default → unreachable, 404).
func WithConformance() Option { return func(p *Peer) { p.conformance = true } }

type opSpec struct {
	op         string
	inputType  string
	outputType string
}

type bootstrapSpec struct {
	pattern string
	name    string
	ops     []opSpec
	make    func(*Peer) handler

	// ownGrants is the handler's OWN grant (§6.8) — the authority it spends when
	// it dispatches onward, as distinct from any capability a caller presents.
	// nil mints the historical empty-grants token, which authorizes nothing.
	//
	// §6.8 row 1: an access in service of a caller's request needs the caller's
	// verified capability AND this grant, and BOTH must pass. A handler that
	// makes an onward dispatch and consults only the presented credential has
	// performed the confused-deputy substitution §6.8 forbids — so this field
	// must be NARROW wherever the handler dispatches onward, or compose and
	// bypass agree on every input and nothing can discriminate between them.
	ownGrants func(*Peer) cbor.Value
}

func coreBootstrapSpecs() []bootstrapSpec {
	return []bootstrapSpec{
		{"system/tree", "Tree", []opSpec{{"get", "", ""}, {"put", "", ""}},
			func(p *Peer) handler { return treeHandler{p} }, nil},
		{"system/handler", "Handlers", []opSpec{
			{"register", "system/handler/register-request", "system/handler/register-result"},
			{"unregister", "system/handler/unregister-request", ""}},
			func(p *Peer) handler { return handlersHandler{p} }, nil},
		{"system/capability", "Capability", []opSpec{
			{"request", "system/capability/request", "system/capability/grant"},
			{"revoke", "system/capability/revoke-request", ""},
			{"configure", "system/capability/policy-entry", ""},
			{"delegate", "system/capability/delegate-request", "system/capability/grant"}},
			func(p *Peer) handler { return capabilityHandler{p} }, nil},
		{"system/protocol/connect", "Connect", []opSpec{{"hello", "", ""}, {"authenticate", "", ""}},
			func(p *Peer) handler { return connectHandler{p} }, nil},
	}
}

func conformanceBootstrapSpecs() []bootstrapSpec {
	return []bootstrapSpec{
		{"system/validate/echo", "validate-echo", []opSpec{{"echo", "", ""}},
			func(p *Peer) handler { return echoHandler{p} }, nil},
		{"system/validate/dispatch-outbound", "validate-dispatch-outbound", []opSpec{{"dispatch", "", ""}},
			func(p *Peer) handler { return dispatchOutboundHandler{p} },
			// NARROW BY DESIGN, and the narrowness is what makes the §6.8
			// intersection measurable. GUIDE-CONFORMANCE §7a.1 ⛔ requires this
			// handler's own grant to cover `echo` on `system/validate/echo` and
			// NOTHING else: with a wide grant, consulting it and skipping it give
			// the same answer on every input, so the confused-deputy
			// discriminator cannot fire and a bypass reads as conformant.
			func(p *Peer) cbor.Value {
				return valList(grantSpec{
					handlers:   []string{"system/validate/echo"},
					operations: []string{"echo"},
					resources:  []string{"system/handler/system/validate/echo"},
				}.toCbor())
			}},
	}
}

func opSpecCbor(in, out string) cbor.Value {
	var pairs []cbor.Pair
	if in != "" {
		pairs = append(pairs, cbor.Entry("input_type", cbor.Text(in)))
	}
	if out != "" {
		pairs = append(pairs, cbor.Entry("output_type", cbor.Text(out)))
	}
	return cbor.NewMap(pairs...)
}

// bootstrapHandlerEntities writes the §6.9 tree entities for a handler: the
// handler entity at the pattern path, the interface at the discovery index, and
// a bootstrap grant.
func (p *Peer) bootstrapHandlerEntities(spec bootstrapSpec) {
	local := p.localPeer
	opPairs := make([]cbor.Pair, len(spec.ops))
	for i, o := range spec.ops {
		opPairs[i] = cbor.Pair{Key: cbor.Text(o.op), Val: opSpecCbor(o.inputType, o.outputType)}
	}
	p.store.Bind("/"+local+"/"+spec.pattern, mustEntity("system/handler", cbor.NewMap(
		cbor.Entry("interface", cbor.Text("system/handler/"+spec.pattern)),
	)))
	p.store.Bind("/"+local+"/system/handler/"+spec.pattern, mustEntity("system/handler/interface", cbor.NewMap(
		cbor.Entry("pattern", cbor.Text(spec.pattern)),
		cbor.Entry("name", cbor.Text(spec.name)),
		cbor.Entry("operations", cbor.NewMap(opPairs...)),
	)))
	// §6.8: the handler's own grant MUST exist at
	// `system/capability/grants/{pattern}` and a handler with no valid grant does
	// not run — so this bind is not optional bookkeeping, it is the ceiling row 1
	// intersects against. An empty grants array is a valid entity that authorizes
	// nothing, which is the right default for a handler that never dispatches
	// onward and the WRONG one for a handler that does.
	grants := cbor.Value{Kind: cbor.KindArray}
	if spec.ownGrants != nil {
		grants = spec.ownGrants(p)
	}
	token, _ := p.mintToken(p.identity.IdentityHash(), grants, nil, nil)
	p.store.Bind("/"+local+"/system/capability/grants/"+spec.pattern, token)
}

// NewPeer constructs + bootstraps a peer from a 32-byte Ed25519 seed.
func NewPeer(seed []byte, opts ...Option) (*Peer, error) {
	identity, err := MakeIdentity(seed)
	if err != nil {
		return nil, err
	}
	p := &Peer{
		identity:  identity,
		store:     NewStore(),
		localPeer: identity.PeerID(),
		handlers:  make(map[string]handler),
	}
	for _, o := range opts {
		o(p)
	}

	// local identity entity in the store (root-granter resolution).
	p.store.PutEntity(identity.PeerEntity())

	// instantiate + register the MUST handlers + write their tree entities.
	for _, spec := range coreBootstrapSpecs() {
		p.handlers[spec.pattern] = spec.make(p)
		p.bootstrapHandlerEntities(spec)
	}

	// publish the V7 §9.5 core type-registry floor (system/type/{name}).
	p.publishCoreTypes()

	// §6.9a Peer Authority Bootstrap: the self-owner capability (root cap, full
	// scope over /{peer_id}/*, grantee = own identity; §6.9a.0 detached-sig
	// shape: cap token at the hex policy path + its self-signature at the §3.5
	// pointer) and the default scope-template entry. open-grants selects the
	// degenerate [default -> *].
	policyBase := "/" + p.localPeer + "/system/capability/policy/"
	ownerToken, ownerSig := p.mintToken(identity.IdentityHash(), grantsCbor(p.ownerGrants()...), nil, nil)
	p.store.Bind(policyBase+hexOf(identity.IdentityHash()), ownerToken)
	p.store.Bind("/"+p.localPeer+"/system/signature/"+hexOf(ownerToken.Hash), ownerSig)

	var defaultGrants cbor.Value
	if p.openGrants {
		defaultGrants = grantsCbor(openGrantsScope()...)
	} else {
		defaultGrants = grantsCbor(discoveryFloor()...)
	}
	defaultEntry := mustEntity("system/capability/policy-entry", cbor.NewMap(
		cbor.Entry("peer_pattern", cbor.Text("default")),
		cbor.Entry("grants", defaultGrants),
	))
	p.store.Bind(policyBase+"default", defaultEntry)

	// §7a conformance handlers — only under --validate.
	if p.conformance {
		for _, spec := range conformanceBootstrapSpecs() {
			p.handlers[spec.pattern] = spec.make(p)
			p.bootstrapHandlerEntities(spec)
		}
	}

	return p, nil
}
