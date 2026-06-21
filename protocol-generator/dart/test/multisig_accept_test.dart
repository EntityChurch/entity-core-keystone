import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:entity_core_protocol/src/codec/ecf_value.dart';
import 'package:test/test.dart';

/// §3.6 M3 multi-signature K-of-N — ACCEPT path.
///
/// The validate-peer `multisig` category is 100% rejection tests (malformed-quorum
/// → 403), which a fail-closed peer passes vacuously. The Go oracle's one
/// accept-path check (`valid_2of3_peer_signed_accepted`) env-skips for the
/// ephemeral run-s4 peer. This unit test covers the direction the oracle omits: a
/// real 2-of-3 multi-sig root (one signer = the local peer, two valid signatures
/// over the cap content_hash) → ALLOW, plus the deny flips (below-threshold M4,
/// duplicate-sig-no-inflate M4, local-not-in-signers M6, threshold=1 M3,
/// duplicate-signers M3, off-root M3) and the single-sig superset (a single-sig
/// root still verifies, unregressed).
///
/// Direct against [verifyCapabilityChain] — the Layer-1 verdict core (§5.10
/// determinism) — with the chain materialized in the envelope's `included` list,
/// exactly as a dispatch request carries it (§5.5).
void main() {
  Uint8List seed(int b) => Uint8List(32)..fillRange(0, 32, b);

  Entity multiSigCap(
      List<Uint8List> signers, int threshold, Uint8List grantee,
      {Uint8List? parent}) {
    final granter = cmap([
      'signers', EcfArray(signers.map((s) => cbytes(s)).toList()),
      'threshold', EcfInt.of(threshold),
    ]);
    final pairs = <Object?>[
      'granter', granter,
      'grantee', cbytes(grantee),
      'grants', EcfArray([
        Peer.grant(['system/tree'], ['system/type/*'], ['get'], null),
      ]),
    ];
    if (parent != null) pairs.addAll(['parent', cbytes(parent)]);
    return Entity.make('system/capability/token', cmap(pairs));
  }

  List<Included> included(List<Entity> entities) =>
      entities.map((e) => Included(e.hash(), e)).toList();

  Future<bool> allows(String local, Entity cap, List<Included> inc) async {
    try {
      return await verifyCapabilityChain(local, Store(), cap, inc) ==
          Verdict.allow;
    } on UnresolvableGrantee {
      return false;
    }
  }

  test('§3.6 M3 multi-sig K-of-N accept-path + deny flips + single-sig superset',
      () async {
    // Three signer identities; id1 is the LOCAL peer (M6).
    final id1 = await Identity.ofSeed(seed(0x11));
    final id2 = await Identity.ofSeed(seed(0x22));
    final id3 = await Identity.ofSeed(seed(0x33));
    final local = id1.peerId;

    final grantee = id1.identityHash();
    final signers = [id1.identityHash(), id2.identityHash(), id3.identityHash()];

    final p1 = id1.peerEntity;
    final p2 = id2.peerEntity;
    final p3 = id3.peerEntity;

    // ── ACCEPT: valid 2-of-3, local in quorum, 2 valid sigs over the cap hash ──
    final cap = multiSigCap(signers, 2, grantee);
    final s1 = await id1.sign(cap);
    final s2 = await id2.sign(cap);
    expect(await allows(local, cap, included([p1, p2, p3, s1, s2])), isTrue,
        reason: '2-of-3 valid quorum (local in signers) -> ALLOW (M3/M4/M6)');

    // M4: only 1 valid sig (< threshold) -> DENY.
    expect(await allows(local, cap, included([p1, p2, p3, s1])), isFalse,
        reason: '1-of-3 below threshold -> DENY (M4 k-of-n)');

    // M4: a DUPLICATE signature from one signer does NOT inflate the count.
    final s1dup = await id1.sign(cap);
    expect(await allows(local, cap, included([p1, p2, p3, s1, s1dup])), isFalse,
        reason: 'duplicate signature from one signer -> DENY (M4)');

    // M6: the local peer is NOT among the signers -> DENY (even with a quorum).
    final capNoLocal =
        multiSigCap([id2.identityHash(), id3.identityHash()], 2, grantee);
    final s2b = await id2.sign(capNoLocal);
    final s3b = await id3.sign(capNoLocal);
    expect(await allows(local, capNoLocal, included([p2, p3, s2b, s3b])),
        isFalse,
        reason: 'local peer not in signers -> DENY (M6)');

    // M3: threshold = 1 (degenerate single disguised as quorum) -> DENY.
    final capT1 = multiSigCap(signers, 1, grantee);
    final s1t = await id1.sign(capT1);
    final s2t = await id2.sign(capT1);
    expect(await allows(local, capT1, included([p1, p2, p3, s1t, s2t])), isFalse,
        reason: 'threshold=1 -> DENY (M3 structure precedence)');

    // M3: duplicate signers in the descriptor -> DENY by structure.
    final capDup =
        multiSigCap([id1.identityHash(), id1.identityHash()], 2, grantee);
    final s1d = await id1.sign(capDup);
    expect(await allows(local, capDup, included([p1, s1d])), isFalse,
        reason: 'duplicate signers in descriptor -> DENY (M3 distinct)');

    // M3 root-only: a multi-sig token WITH a parent (off-root) -> DENY.
    final multiWithParent = multiSigCap(
        [id1.identityHash(), id2.identityHash()], 2, grantee,
        parent: p1.hash());
    expect(await allows(local, multiWithParent, included([p1, p2])), isFalse,
        reason: 'multi-sig token with a parent (off-root) -> DENY (M3 root-only)');

    // ── single-sig superset: a normal single-sig root still verifies. ──
    final singleRoot = Entity.make(
        'system/capability/token',
        cmap([
          'granter', cbytes(id1.identityHash()),
          'grantee', cbytes(id1.identityHash()),
          'grants', EcfArray([
            Peer.grant(['system/tree'], ['system/type/*'], ['get'], null),
          ]),
        ]));
    final singleSig = await id1.sign(singleRoot);
    expect(await allows(local, singleRoot, included([p1, singleSig])), isTrue,
        reason: 'single-sig root rooted at local still verifies (superset)');
  });
}
