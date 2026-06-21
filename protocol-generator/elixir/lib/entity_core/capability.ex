defmodule EntityCore.Capability do
  @moduledoc """
  Capability system (L3) — the §5 verification core: pattern matching (§5.4),
  request verification (§5.2 `verify_request` / `check_permission`),
  delegation-chain verification (§5.5), attenuation (§5.6), and §5.7 caveats.

  Spec-first stance: derived from the §5 pseudocode. The chain verdict is
  `:allow | :deny | :unresolvable_grantee` — the dispatcher maps `:deny` → 403 and
  the §5.5 `:unresolvable_grantee` carve-out → 401. `verify_request/3` returns the
  3-way `:req_allow | :req_authn_fail | :req_authz_deny` so the dispatcher can draw
  the §4.6 / F20 authn(401)-vs-authz(403) boundary.

  §PR-8 / §5.5a (v7.73): a cap's grant *resource* patterns canonicalize against the
  GRANTER's peer_id (the per-link granter frame), NOT the verifier's. Every other
  dimension (operation/handler/peer) stays on the local frame. The preferred
  HARD-FAIL on an unresolvable per-link granter (deny, never a silent local-frame
  fallback) is applied per the Amendment-1 §4 scrutiny.
  """

  alias EntityCore.{Identity, Model, Store}
  alias EntityCore.Model.Envelope

  @max_chain_depth 64

  # ── parse helpers ───────────────────────────────────────────────────────

  defp text_list(l) when is_list(l), do: Enum.filter(l, &is_binary/1)
  defp text_list(_), do: []

  defp parse_scope(c) do
    %{incl: text_list(Model.map_get(c, "include")), excl: text_list(Model.map_get(c, "exclude"))}
  end

  defp parse_grant(c) do
    sc = fn key ->
      case Model.map_get(c, key) do
        nil -> %{incl: [], excl: []}
        s -> parse_scope(s)
      end
    end

    %{
      handlers: sc.("handlers"),
      resources: sc.("resources"),
      operations: sc.("operations"),
      peers: (case Model.map_get(c, "peers") do
                nil -> nil
                s -> parse_scope(s)
              end)
    }
  end

  @doc "Parse a single grant-entry CBOR value into the internal grant shape."
  def parse_grant_entry(c), do: parse_grant(c)

  @doc "The grants of a `system/capability/token` entity."
  def grants_of_token(token) do
    case Model.field(token, "grants") do
      l when is_list(l) -> Enum.map(l, &parse_grant/1)
      _ -> []
    end
  end

  # ── §5.4 pattern matching ─────────────────────────────────────────────────

  @doc "Is `seg` a plausible Base58 peer-id (≥46 chars, Base58 alphabet)?"
  def is_peer_id(seg) do
    byte_size(seg) >= 46 and
      seg |> String.to_charlist() |> Enum.all?(fn c -> String.contains?(EntityCore.Base58.alphabet(), <<c>>) end)
  end

  @doc "URI normalization (§1.4): strip `entity://` and prepend `/`; pass others through."
  def normalize_uri("entity://" <> rest), do: "/" <> rest
  def normalize_uri(uri), do: uri

  @doc """
  Resolve a peer-relative path to absolute `/{local}/...` form. Raises on the
  reserved directory-relative (`./`, `../`) and bare-peer-wildcard (`*/`) forms.
  """
  def canonicalize(local_peer, path) do
    cond do
      String.starts_with?(path, "./") or String.starts_with?(path, "../") ->
        raise ArgumentError, "canonicalize: reserved directory-relative path"

      String.starts_with?(path, "*/") ->
        raise ArgumentError, "canonicalize: ambiguous bare peer wildcard"

      String.starts_with?(path, "/") ->
        path

      true ->
        "/" <> local_peer <> "/" <> path
    end
  end

  # find the first '/' at or after byte index `start`, or nil.
  defp slash_from(s, start) when byte_size(s) > start do
    case :binary.match(s, "/", scope: {start, byte_size(s) - start}) do
      {i, _} -> i
      :nomatch -> nil
    end
  end

  defp slash_from(_s, _start), do: nil

  @doc "Match a canonical (absolute) `path` against a canonical `pattern` (§5.4)."
  def matches_pattern(_path, "*"), do: true

  def matches_pattern(path, pattern) do
    cond do
      String.starts_with?(pattern, "/*/") ->
        remainder = binary_part(pattern, 3, byte_size(pattern) - 3)

        case slash_from(path, 1) do
          nil -> false
          i -> matches_pattern(binary_part(path, i + 1, byte_size(path) - i - 1), remainder)
        end

      byte_size(pattern) >= 2 and String.ends_with?(pattern, "/*") ->
        # keep the trailing slash: "/a/b/*" → prefix "/a/b/"
        prefix = binary_part(pattern, 0, byte_size(pattern) - 1)
        String.starts_with?(path, prefix)

      true ->
        path == pattern
    end
  end

  defp matches_scope(local_peer, value, s) do
    cv = canonicalize(local_peer, value)
    covered = fn pats -> Enum.any?(pats, fn p -> matches_pattern(cv, canonicalize(local_peer, p)) end) end
    if not covered.(s.incl), do: false, else: not covered.(s.excl)
  end

  # ── §5.2 check_permission ─────────────────────────────────────────────────

  defp first_segment(uri) do
    uri = if String.starts_with?(uri, "/"), do: binary_part(uri, 1, byte_size(uri) - 1), else: uri

    case :binary.match(uri, "/") do
      {i, _} -> binary_part(uri, 0, i)
      :nomatch -> uri
    end
  end

  @doc "The target peer of a URI: a leading peer-id segment, else the local peer (§1.4)."
  def extract_peer(local_peer, uri) do
    first = first_segment(normalize_uri(uri))
    if is_peer_id(first), do: first, else: local_peer
  end

  # check_resource_scope (§5.4 + §PR-8): the GRANT's resource patterns canonicalize
  # against the GRANTER frame; the request target + caller-supplied exclude stay
  # on the local/request frame.
  defp check_resource_scope(local_peer, granter_peer, resource, s) do
    targets = text_list(Model.map_get(resource, "targets"))
    caller_excl = text_list(Model.map_get(resource, "exclude"))
    covered_local = fn pats, v -> Enum.any?(pats, fn p -> matches_pattern(v, canonicalize(local_peer, p)) end) end
    covered_grant = fn pats, v -> Enum.any?(pats, fn p -> matches_pattern(v, canonicalize(granter_peer, p)) end) end

    targets != [] and
      Enum.all?(targets, fn tgt ->
        ct = canonicalize(local_peer, tgt)

        cond do
          covered_local.(caller_excl, ct) -> true
          not covered_grant.(s.incl, ct) -> false
          true -> not covered_grant.(s.excl, ct)
        end
      end)
  end

  @doc """
  Resolve the §PR-8 granter frame for a leaf cap's grant resource patterns: the
  granter's peer_id, or `nil` (multisig / unresolvable → caller falls back to the
  local peer). `resolve_fn` is the included-then-store lookup.
  """
  def resolve_granter_peer_id(resolve_fn, cap) do
    case Model.bytes_field(cap, "granter") do
      nil ->
        nil

      gh ->
        with %{} = g <- resolve_fn.(gh),
             pk when is_binary(pk) <- Model.bytes_field(g, "public_key") do
          Identity.peer_id_of_pubkey(pk)
        else
          _ -> nil
        end
    end
  end

  @doc """
  Gate a wire request at the dispatch authorization boundary (§5.2 / §3.2.3).
  `granter_peer` is the §PR-8 frame for the cap's grant resource patterns; every
  other dimension stays on the local frame.
  """
  def check_permission(local_peer, granter_peer, exec, token, handler_pattern) do
    operation = Model.text_field(exec, "operation") || ""
    uri = Model.text_field(exec, "uri") || ""
    target_peer = extract_peer(local_peer, uri)
    resource = Model.field(exec, "resource")

    grant_ok = fn g ->
      matches_scope(local_peer, operation, g.operations) and
        matches_scope(local_peer, handler_pattern, g.handlers) and
        (let_peers = g.peers || %{incl: [local_peer], excl: []}
         matches_scope(local_peer, target_peer, let_peers)) and
        (case resource do
           nil -> true
           r -> check_resource_scope(local_peer, granter_peer, r, g.resources)
         end)
    end

    if Enum.any?(grants_of_token(token), grant_ok), do: :allow, else: :deny
  end

  # ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────

  defp now_ms, do: System.system_time(:millisecond)

  @doc "Find a `system/signature` in `included` whose `target` equals `target`."
  def find_signature(target, included) do
    Enum.find_value(included, fn {_h, e} ->
      if e.type == "system/signature" and Model.bytes_field(e, "target") == target, do: e, else: nil
    end)
  end

  # included-then-store resolution by content_hash.
  defp resolve(included, store) do
    fn h ->
      case Map.get(included, h) do
        nil -> Store.get_by_hash(store, h)
        e -> e
      end
    end
  end

  # link_granter_peer (§5.5a): the per-link frame for a chain link's resource
  # patterns. Single-sig granter → granter peer_id; multi-sig root (no granter)
  # → local frame; PREFERRED HARD-FAIL (nil → caller denies) on an unresolvable
  # granter or a resolved identity with no public_key.
  defp link_granter_peer(resolve_fn, local_peer, cap) do
    case Model.bytes_field(cap, "granter") do
      nil ->
        local_peer

      gh ->
        with %{} = g <- resolve_fn.(gh),
             pk when is_binary(pk) <- Model.bytes_field(g, "public_key") do
          Identity.peer_id_of_pubkey(pk)
        else
          _ -> nil
        end
    end
  end

  # scope_subset (§5.6 + §5.5a): every child include covered by parent include;
  # child inherits all parent excludes. Each side canonicalizes against its own
  # per-link granter frame.
  defp scope_subset(child_peer, parent_peer, child, parent) do
    Enum.all?(child.incl, fn cp ->
      cc = canonicalize(child_peer, cp)
      Enum.any?(parent.incl, fn pp -> matches_pattern(cc, canonicalize(parent_peer, pp)) end)
    end) and
      Enum.all?(parent.excl, fn pe ->
        cpe = canonicalize(parent_peer, pe)
        Enum.any?(child.excl, fn ce -> matches_pattern(cpe, canonicalize(child_peer, ce)) end)
      end)
  end

  defp grant_subset(local_peer, child_peer, parent_peer, child, parent) do
    scope_subset(local_peer, local_peer, child.handlers, parent.handlers) and
      scope_subset(local_peer, local_peer, child.operations, parent.operations) and
      scope_subset(child_peer, parent_peer, child.resources, parent.resources) and
      (cp = child.peers || %{incl: [local_peer], excl: []}
       pp = parent.peers || %{incl: [local_peer], excl: []}
       scope_subset(local_peer, local_peer, cp, pp))
  end

  @doc "§6.2 mint-time subset check (capability-handler surface, local frame)."
  def grant_subset_local(local_peer, child, parent),
    do: grant_subset(local_peer, local_peer, local_peer, child, parent)

  defp is_attenuated(local_peer, child_peer, parent_peer, child, parent) do
    cg = grants_of_token(child)
    pg = grants_of_token(parent)

    grants_ok =
      Enum.all?(cg, fn c ->
        Enum.any?(pg, fn p -> grant_subset(local_peer, child_peer, parent_peer, c, p) end)
      end)

    grants_ok and
      case {Model.uint_field(parent, "expires_at"), Model.uint_field(child, "expires_at")} do
        # child infinite, parent finite → not attenuated
        {pe, nil} when pe != nil -> false
        {pe, ce} when pe != nil and ce != nil -> ce <= pe
        {nil, _} -> true
      end
  end

  # §5.7 delegation caveats — parent's caveats constrain its direct child.
  defp check_delegation_caveats(parent, child, depth) do
    case Model.field(parent, "delegation_caveats") do
      nil ->
        true

      caveats ->
        no_deleg =
          case Model.map_get(caveats, "no_delegation") do
            b when is_boolean(b) -> b
            _ -> false
          end

        if no_deleg do
          false
        else
          depth_ok =
            case Model.map_get(caveats, "max_delegation_depth") do
              m when is_integer(m) -> depth < m
              _ -> true
            end

          ttl_ok =
            case Model.map_get(caveats, "max_delegation_ttl") do
              maxttl when is_integer(maxttl) ->
                case {Model.uint_field(child, "expires_at"), Model.uint_field(child, "created_at")} do
                  {ex, cr} when ex != nil and cr != nil -> ex - cr <= maxttl
                  {ex, nil} when ex != nil -> true
                  {nil, _} -> false
                end

              _ ->
                true
            end

          depth_ok and ttl_ok
        end
    end
  end

  # collect_authority_chain (§5.5) — walk to root via parent hashes.
  defp collect_chain(cap, resolve_fn) do
    go = fn go, current, depth, acc ->
      if depth > @max_chain_depth do
        {:error, :chain_too_deep}
      else
        acc = [current | acc]

        case Model.bytes_field(current, "parent") do
          nil ->
            {:ok, Enum.reverse(acc)}

          ph ->
            case resolve_fn.(ph) do
              nil -> {:error, :chain_unreachable}
              parent -> go.(go, parent, depth + 1, acc)
            end
        end
      end
    end

    go.(go, cap, 0, [])
  end

  # ── §3.6 M3 multi-signature granter ───────────────────────────────────────
  # A cap's `granter` field is a union (§3.6): a single `system/hash` (single-sig,
  # carried as `{:bytes, _}`) or a `{signers: [system/hash], threshold: uint}`
  # descriptor (multi-sig, root-only — carried as a map). A multi-sig root is
  # verified by `verify_multisig_root/5` — M3 structure first, then §5.5 M6
  # root-at-local + M4 k-of-n quorum.

  @doc """
  Parse a §3.6 multi-granter descriptor from a cap (or `nil` for single-sig). The
  granter is multi-sig iff it is a CBOR map; `signers` is its array of hash bytes
  and `threshold` its uint (defaulting to 0 when absent/ill-typed, so a malformed
  descriptor fails M3 structure rather than crashing).
  """
  def multi_granter(cap) do
    case Model.field(cap, "granter") do
      g when is_map(g) ->
        signers =
          case Model.map_get(g, "signers") do
            l when is_list(l) -> for {:bytes, b} <- l, do: b
            _ -> []
          end

        threshold =
          case Model.map_get(g, "threshold") do
            t when is_integer(t) and t >= 0 -> t
            _ -> 0
          end

        %{signers: signers, threshold: threshold}

      _ ->
        nil
    end
  end

  @doc "Is `cap`'s granter a §3.6 multi-sig descriptor (a map, not a single hash)?"
  def multisig?(cap), do: multi_granter(cap) != nil

  # All `system/signature` entities in the `included` map whose `target` == hash.
  defp signatures_targeting(target, included) do
    for {_h, e} <- included,
        e.type == "system/signature",
        Model.bytes_field(e, "target") == target,
        do: e
  end

  @doc """
  verify_multisig_root (§3.6 M3 / §5.5 M4·M6) → boolean. ALLOW only if the quorum
  is well-formed AND a threshold of DISTINCT signers signed the cap's content hash.
  Structural validation (M3) precedes signature counting (§3.6 precedence 25): a
  malformed quorum is denied on its structure, not its signatures. Every path
  returns a bool → the dispatcher maps `false` to 403 capability_denied; nothing
  here raises.
  """
  def verify_multisig_root(local_peer, resolve_fn, cap, %{signers: signers, threshold: threshold}, included) do
    n = length(signers)

    peer_id_of = fn h ->
      with %{} = p <- resolve_fn.(h),
           pk when is_binary(pk) <- Model.bytes_field(p, "public_key") do
        Identity.peer_id_of_pubkey(pk)
      else
        _ -> nil
      end
    end

    # §3.6 M3 structure — root-only; real quorum (n ≥ 2); usable threshold
    # (2 ≤ threshold ≤ n); distinct signers. Checked BEFORE signatures.
    structure_ok =
      Model.bytes_field(cap, "parent") == nil and
        n >= 2 and threshold >= 2 and threshold <= n and
        length(Enum.uniq(signers)) == n

    cond do
      not structure_ok ->
        false

      # §5.5 M6 — the local peer MUST be one of the quorum members.
      not Enum.any?(signers, fn s -> peer_id_of.(s) == local_peer end) ->
        false

      # temporal validity (as for any root).
      not temporal_ok(cap, now_ms()) ->
        false

      # grantee resolution (as for any root).
      not (case Model.bytes_field(cap, "grantee") do
             nil -> false
             gh -> resolve_fn.(gh) != nil
           end) ->
        false

      true ->
        # §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the
        # cap's content hash; ≥ threshold ⇒ quorum. A duplicate signature from one
        # signer never inflates the count (we count distinct signer hashes).
        sigs = signatures_targeting(cap.hash, included)

        valid =
          signers
          |> Enum.uniq()
          |> Enum.count(fn s ->
            case resolve_fn.(s) do
              %{} = signer_peer ->
                Enum.any?(sigs, fn sgn ->
                  Model.bytes_field(sgn, "signer") == s and
                    Identity.verify_signature(sgn, signer_peer)
                end)

              _ ->
                false
            end
          end)

        valid >= threshold
    end
  end

  @doc """
  verify_capability_chain (§5.5). A single-sig root must root at the local peer; a
  §3.6 M3 multi-sig root (root-only) must pass k-of-n quorum verification (a
  multi-sig token anywhere but the chain root is rejected). Returns
  `:allow | :deny | :unresolvable_grantee`.
  """
  # §4.10(b) structural-bound pre-check: true if the authority chain rooted at
  # `capability` exceeds @max_chain_depth. Walks parent pointers without verifying
  # signatures — depth is a purely structural property, gated BEFORE the per-link
  # authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
  # (structural excess), distinct from a 403 capability_denied authz failure (arch
  # ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
  # returns false here and is left for verify_capability_chain to deny (403).
  def chain_exceeds_depth?(store, capability, included) do
    resolve_fn = resolve(included, store)

    go = fn go, current, depth ->
      cond do
        depth > @max_chain_depth ->
          true

        true ->
          case Model.bytes_field(current, "parent") do
            nil ->
              false

            ph ->
              case resolve_fn.(ph) do
                nil -> false
                parent -> go.(go, parent, depth + 1)
              end
          end
      end
    end

    go.(go, capability, 0)
  end

  def verify_capability_chain(local_peer, store, capability, included) do
    resolve_fn = resolve(included, store)

    case collect_chain(capability, resolve_fn) do
      {:error, _} ->
        :deny

      {:ok, chain} ->
        root = List.last(chain)

        # Root authority: a §3.6 M3 multi-sig root (root-only) passes k-of-n quorum
        # verification; a single-sig root must root at the local peer.
        root_ok =
          case multi_granter(root) do
            %{} = mg ->
              verify_multisig_root(local_peer, resolve_fn, root, mg, included)

            nil ->
              case Model.bytes_field(root, "granter") do
                nil ->
                  false

                gh ->
                  case resolve_fn.(gh) do
                    %{} = g ->
                      case Model.bytes_field(g, "public_key") do
                        pk when is_binary(pk) -> Identity.peer_id_of_pubkey(pk) == local_peer
                        _ -> false
                      end

                    _ ->
                      false
                  end
              end
          end

        if not root_ok, do: :deny, else: walk_chain(local_peer, store, included, resolve_fn, chain)
    end
  end

  # Walk the chain links, returning the verdict (or :unresolvable_grantee). Uses
  # a reduce_while: the running state is the verdict accumulator.
  defp walk_chain(local_peer, _store, included, resolve_fn, chain) do
    n = length(chain)
    t = now_ms()

    Enum.reduce_while(Enum.with_index(chain), :allow, fn {current, i}, _acc ->
      cond do
        # §3.6 M3 multi-sig is root-only: it is fully verified above (structure,
        # quorum signatures, temporal, grantee), so the per-link single-sig checks
        # are skipped at the root — but a multi-sig token anywhere else denies.
        multisig?(current) ->
          if i == n - 1, do: {:cont, :allow}, else: {:halt, :deny}

        # signature: signer == granter, verify against granter identity
        not link_signature_ok(current, included, resolve_fn) ->
          {:halt, :deny}

        # grantee resolution → 401 carve-out
        not grantee_resolvable(current, resolve_fn) ->
          {:halt, :unresolvable_grantee}

        # temporal validity
        not temporal_ok(current, t) ->
          {:halt, :deny}

        # delegation link (parent.grantee == current.granter, attenuation, caveats)
        i < n - 1 ->
          parent = Enum.at(chain, i + 1)
          child_peer = link_granter_peer(resolve_fn, local_peer, current)
          parent_peer = link_granter_peer(resolve_fn, local_peer, parent)

          if child_peer == nil or parent_peer == nil do
            {:halt, :deny}
          else
            link_ok =
              (case {Model.bytes_field(parent, "grantee"), Model.bytes_field(current, "granter")} do
                 {pg, cg} when pg != nil and cg != nil -> pg == cg
                 _ -> false
               end) and
                is_attenuated(local_peer, child_peer, parent_peer, current, parent) and
                check_delegation_caveats(parent, current, i)

            if link_ok, do: {:cont, :allow}, else: {:halt, :deny}
          end

        true ->
          {:cont, :allow}
      end
    end)
  end

  defp link_signature_ok(current, included, resolve_fn) do
    case Model.bytes_field(current, "granter") do
      nil ->
        false

      gh ->
        case {find_signature(current.hash, included), resolve_fn.(gh)} do
          {%{} = sgn, %{} = granter} ->
            (Model.bytes_field(sgn, "signer") == gh) and Identity.verify_signature(sgn, granter)

          _ ->
            false
        end
    end
  end

  defp grantee_resolvable(current, resolve_fn) do
    case Model.bytes_field(current, "grantee") do
      nil -> false
      gh -> resolve_fn.(gh) != nil
    end
  end

  defp temporal_ok(current, t) do
    nb_ok =
      case Model.uint_field(current, "not_before") do
        nb when nb != nil -> t >= nb
        _ -> true
      end

    ex_ok =
      case Model.uint_field(current, "expires_at") do
        ex when ex != nil -> ex >= t
        _ -> true
      end

    nb_ok and ex_ok
  end

  @doc "is_revoked (§5.1) — marker check covering the leaf cap and the chain root."
  def is_revoked(local_peer, store, capability, included) do
    resolve_fn = resolve(included, store)

    root_hash =
      case collect_chain(capability, resolve_fn) do
        {:ok, chain} -> List.last(chain).hash
        {:error, _} -> capability.hash
      end

    check = fn h ->
      Store.get_at(store, "/" <> local_peer <> "/system/capability/revocations/" <> Model.hex(h)) != nil
    end

    check.(capability.hash) or check.(root_hash)
  end

  # ── §5.2 verify_request (3-way authn/authz verdict) ────────────────────────

  @doc """
  verify_request (§5.2) → `:req_allow | :req_authn_fail | :req_authz_deny`.

  Authentication-class failures (signature/author can't be established) → 401 (F20
  / A-OC-008 boundary; §5.2's flat "DENY → 403" under-specifies the §4.6 split).
  Authorization DENY → 403. The §5.5 `:unresolvable_grantee` is surfaced as a
  distinct tuple so the dispatcher maps it to 401 (the single carve-out), taking
  precedence over the §5.2 grantee==author 403.
  """
  def verify_request(local_peer, store, %Envelope{} = env) do
    exec = env.root
    included = env.included

    # signature / author — authentication class (§4.6 → 401).
    case find_signature(exec.hash, included) do
      nil ->
        :req_authn_fail

      sgn ->
        author_h = Model.bytes_field(exec, "author")
        signer_ok = author_h != nil and Model.bytes_field(sgn, "signer") == author_h

        cond do
          not signer_ok ->
            :req_authn_fail

          true ->
            case author_h && Model.included_get(env, author_h) do
              nil ->
                :req_authn_fail

              author ->
                if not Identity.verify_signature(sgn, author) do
                  :req_authn_fail
                else
                  authorize(local_peer, store, env, exec, author_h, included)
                end
            end
        end
    end
  end

  defp authorize(local_peer, store, env, exec, author_h, included) do
    case Model.bytes_field(exec, "capability") && Model.included_get(env, Model.bytes_field(exec, "capability")) do
      nil ->
        :req_authz_deny

      capability ->
        # §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
        # chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
        # distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the caller
        # distinguish "shorten your chain" from "you lack the capability".
        if chain_exceeds_depth?(store, capability, included) do
          :req_chain_too_deep
        else
        # Chain verification first: a per-link unresolvable grantee (§5.5) → 401
        # MUST take precedence over the §5.2 grantee==author mismatch → 403.
        case verify_capability_chain(local_peer, store, capability, included) do
          :unresolvable_grantee ->
            :unresolvable_grantee

          :deny ->
            :req_authz_deny

          :allow ->
            grantee_ok =
              (case {Model.bytes_field(capability, "grantee"), author_h} do
                 {g, a} when g != nil and a != nil -> g == a
                 _ -> false
               end)

            cond do
              not grantee_ok -> :req_authz_deny
              is_revoked(local_peer, store, capability, included) -> :req_authz_deny
              true -> :req_allow
            end
        end
        end
    end
  end
end
