defmodule EntityCore.MultisigTest do
  @moduledoc """
  §3.6 M3 multi-signature K-of-N — the ACCEPT path the oracle omits.

  The validate-peer `multisig` category is 100% rejection tests (a malformed
  quorum → 403), which a fail-closed peer passes 10/10 without any genuine k-of-n
  understanding. This is the direction the oracle does NOT cover: a well-formed
  2-of-3 root (one signer = the local peer) carrying a threshold of valid
  signatures over the cap's content hash MUST be ALLOWed — and each M3/M4/M6
  invariant flip MUST deny. Mirrors the OCaml `selftest.ml` accept-path block.
  """
  use ExUnit.Case, async: true

  alias EntityCore.{Capability, Identity, Model, Store}

  # Build the §3.6 multi-granter descriptor: {signers: [hash], threshold: uint}.
  defp granter_map(signer_ids, threshold) do
    %{
      "signers" => for(id <- signer_ids, do: {:bytes, id.identity_hash}),
      "threshold" => threshold
    }
  end

  # A multi-sig capability token (grantee = id1, root-only unless `parent` given).
  defp mk_cap(signer_ids, threshold, grantee, opts \\ []) do
    base = %{
      "granter" => granter_map(signer_ids, threshold),
      "grantee" => {:bytes, grantee.identity_hash},
      "grants" => []
    }

    data =
      case Keyword.get(opts, :parent) do
        nil -> base
        ph -> Map.put(base, "parent", {:bytes, ph})
      end

    Model.make("system/capability/token", data)
  end

  # An `included` map (content_hash → entity) from a list of entities.
  defp included(entities), do: for(e <- entities, into: %{}, do: {e.hash, e})

  setup do
    {:ok, store} = Store.start_link()
    id1 = Identity.of_seed(:binary.copy(<<1>>, 32))
    id2 = Identity.of_seed(:binary.copy(<<2>>, 32))
    id3 = Identity.of_seed(:binary.copy(<<3>>, 32))
    # The local peer is one of the three signers (M6 satisfied for the happy path).
    %{store: store, local: id1.peer_id, id1: id1, id2: id2, id3: id3}
  end

  defp allows?(store, local, cap, inc),
    do: Capability.verify_capability_chain(local, store, cap, inc) == :allow

  test "valid 2-of-3 quorum (local in signers, 2 valid sigs) → Allow",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    cap = mk_cap([id1, id2, id3], 2, id1)
    s1 = Identity.sign_entity(id1, cap)
    s2 = Identity.sign_entity(id2, cap)
    inc = included([id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s2])
    assert allows?(store, local, cap, inc)
  end

  test "only 1 valid signature (below threshold) → Deny (M4)",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    cap = mk_cap([id1, id2, id3], 2, id1)
    s1 = Identity.sign_entity(id1, cap)
    inc = included([id1.peer_entity, id2.peer_entity, id3.peer_entity, s1])
    refute allows?(store, local, cap, inc)
  end

  test "local peer not among signers → Deny (M6)",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    cap = mk_cap([id2, id3], 2, id1)
    s2 = Identity.sign_entity(id2, cap)
    s3 = Identity.sign_entity(id3, cap)
    inc = included([id1.peer_entity, id2.peer_entity, id3.peer_entity, s2, s3])
    refute allows?(store, local, cap, inc)
  end

  test "threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    cap = mk_cap([id1, id2, id3], 1, id1)
    s1 = Identity.sign_entity(id1, cap)
    s2 = Identity.sign_entity(id2, cap)
    inc = included([id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s2])
    refute allows?(store, local, cap, inc)
  end

  test "duplicate signers (M3 structure) → Deny",
       %{store: store, local: local, id1: id1} do
    cap = mk_cap([id1, id1], 2, id1)
    s1 = Identity.sign_entity(id1, cap)
    inc = included([id1.peer_entity, s1])
    refute allows?(store, local, cap, inc)
  end

  test "duplicate signature from one signer does not inflate the count → Deny (M4)",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    # 3 distinct signers, threshold 2, but only id1 signs (twice). Distinct count = 1.
    cap = mk_cap([id1, id2, id3], 2, id1)
    s1a = Identity.sign_entity(id1, cap)
    s1b = Identity.sign_entity(id1, cap)
    inc = included([id1.peer_entity, id2.peer_entity, id3.peer_entity, s1a, s1b])
    refute allows?(store, local, cap, inc)
  end

  test "multi-sig token off the chain root → Deny (root-only)",
       %{store: store, local: local, id1: id1, id2: id2, id3: id3} do
    # A genuine multi-sig root, plus a child cap whose parent is the multi-sig
    # token. The leaf is verified by walking to the root; the multi-sig node is
    # not the root here, so the chain denies.
    ms_root = mk_cap([id1, id2, id3], 2, id1)
    s1 = Identity.sign_entity(id1, ms_root)
    s2 = Identity.sign_entity(id2, ms_root)

    # A single-sig child delegating from the multi-sig root would itself need a
    # single-sig granter; instead make the leaf ALSO multi-sig with the root as
    # parent — directly exercising "multi-sig off root denies".
    leaf = mk_cap([id1, id2, id3], 2, id1, parent: ms_root.hash)
    ls1 = Identity.sign_entity(id1, leaf)
    ls2 = Identity.sign_entity(id2, leaf)

    inc =
      included([
        id1.peer_entity,
        id2.peer_entity,
        id3.peer_entity,
        ms_root,
        leaf,
        s1,
        s2,
        ls1,
        ls2
      ])

    refute allows?(store, local, leaf, inc)
  end

  test "single-sig root still verifies (strict superset)",
       %{store: store, local: local, id1: id1} do
    ss_cap =
      Model.make("system/capability/token", %{
        "granter" => {:bytes, id1.identity_hash},
        "grantee" => {:bytes, id1.identity_hash},
        "grants" => []
      })

    sig = Identity.sign_entity(id1, ss_cap)
    inc = included([id1.peer_entity, sig])
    assert allows?(store, local, ss_cap, inc)
  end
end
