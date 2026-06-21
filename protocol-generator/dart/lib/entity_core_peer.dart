/// entity_core_peer — the V7 Layer 1–4 peer machinery surface (S3), built on top
/// of the S2 codec (`entity_core_protocol`).
///
/// The peer brain ([Peer]) + transport ([startListener] / [dial]) + the value
/// types (Entity, Envelope, Identity, Store) needed to host or drive a core
/// protocol peer over real TCP. The extension surface stops at the [Handler]
/// dispatcher interface — community installs handlers above that boundary.
library;

export 'src/peer/capability.dart'
    show
        Verdict,
        RequestVerdict,
        verifyCapabilityChain,
        verifyRequest,
        chainExceedsDepth,
        UnresolvableGrantee;
export 'src/peer/cbor.dart';
export 'src/peer/core_types.dart' show coreTypeModels, coreTypeEntities;
export 'src/peer/dispatch.dart';
export 'src/peer/entity.dart';
export 'src/peer/envelope.dart';
export 'src/peer/identity.dart';
export 'src/peer/peer.dart';
export 'src/peer/store.dart';
export 'src/peer/transport.dart';
export 'src/peer/wire.dart';
