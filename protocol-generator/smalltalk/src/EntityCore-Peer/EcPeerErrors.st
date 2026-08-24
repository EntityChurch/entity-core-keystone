"entity-core-protocol-smalltalk — the PEER-layer Error subclasses (EntityCore-Peer),
extending the S2 EntityCoreError tree from EcErrors.st (per profile [error_model]).

The wire dispatch NEVER lets one of these propagate to a silent drop: the §4.9
deliver-or-signal rule means a decodable EXECUTE always gets an EXECUTE_RESPONSE, so the
dispatcher catches EntityCoreError at the boundary and maps it to a coded status (§6.12).

  EntityProtocolError  — a malformed/invalid protocol shape (→ 400/500 at the boundary)
    EcWireError        — a bad envelope / entity wire shape (§3.1 fidelity)
    EcHelloFailedError / EcAuthenticationError — the §4.1 handshake legs
  EntityTransportError — a per-request transport failure (§6.12)
    EcRecvTimeoutError / EcConnectionBrokenError

LIVE-IMAGE NOTE (A-ST-010): each class installed off its parent class object; the parents
(EntityCoreError, EntityProtocolError, EntityTransportError) are globally registered by the
time this doit runs (EcErrors loads first, and the two intermediate parents are installed +
referenced across statements here, not by not-yet-registered global name in one expression)."

| pkg core proto transport |
pkg := 'EntityCore-Peer'.

core := Smalltalk at: #EntityCoreError.

proto := (core << #EntityProtocolError package: pkg) install.
(proto << #EcWireError package: pkg) install.
(proto << #EcHelloFailedError package: pkg) install.
(proto << #EcAuthenticationError package: pkg) install.

transport := (core << #EntityTransportError package: pkg) install.
(transport << #EcRecvTimeoutError package: pkg) install.
(transport << #EcConnectionBrokenError package: pkg) install.

'EntityCore-Peer:EcPeerErrors installed'
