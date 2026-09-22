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

  # The unmatchable value (0.8.2.20). Unreachable as a canonical path by
  # CONSTRUCTION: its first segment cannot be a peer_id, since is_peer_id requires
  # >= 46 Base58 characters and "-" is outside the Base58 alphabet.
  @never_match "/never-match"

  @doc """
  The unmatchable value (0.8.2.20) — see `canonicalize/2`.
  """
  def never_match, do: @never_match

  @doc """
  Resolve a peer-relative path to absolute `/{local}/...` form.

  TOTAL (0.8.2.20): the return domain is "a canonical path OR `#{@never_match}`".
  This used to RAISE, and the raise was reachable from the wire — every normative
  call site is a matcher with no error channel to consume one, so the exception
  escaped the matcher, the resilience frame caught it, and `../x` in a resource
  exclude answered 500 (measured 2026-09-14). The diagnostic belongs at admission
  (§6.5), which has a caller to answer.
  """
  def canonicalize(local_peer, path) do
    cond do
      String.starts_with?(path, "./") or String.starts_with?(path, "../") ->
        @never_match

      String.starts_with?(path, "*/") ->
        @never_match

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
  # @never_match never matches, in EITHER operand (0.8.2.20). These clauses are FIRST,
  # and the rule is a matcher rule rather than a property of the string: the clause
  # below returns true for a bare "*" pattern, so safety must not rest on a value
  # merely looking unmatchable.
  def matches_pattern(@never_match, _pattern), do: false
  def matches_pattern(_path, @never_match), do: false
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

  @doc """
  §5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal comparison with
  exactly two wildcard forms: bare `*` and a trailing slash-star segment-prefix. None of
  the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
  literal string: a non-match, never a fault.
  """
  def matches_id_pattern(_value, "*"), do: true

  def matches_id_pattern(value, pattern) do
    if byte_size(pattern) >= 2 and String.ends_with?(pattern, "/*") do
      String.starts_with?(value, binary_part(pattern, 0, byte_size(pattern) - 1))
    else
      value == pattern
    end
  end

  # §5.2 typed scope match. `kind` is `:id` (operations, peers) or `:path` (handlers,
  # resources) and has no default — every call site names its dimension, so a new one
  # cannot silently inherit the wrong matcher, which is exactly the F40 defect.
  #
  # AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
  # in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
  # exclude (carves out nothing -> the grant is SILENTLY WIDER than its author wrote):
  # same value, same matcher, opposite safety direction, so the reading is chosen where
  # the POSITION is known and matches_pattern stays uniform over its operands.
  #
  # ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). `@never_match` is a §5.4
  # PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that
  # §5.2's own id-scope arm forbids putting through the §5.4 transforms. This guard used
  # to sit OUTSIDE the type dispatch, transcribing §5.2's loop as it read before that
  # loop grew one — which ran an id pattern through those transforms purely to classify
  # it and then DENIED THE WHOLE DIMENSION on a property unrelated to whether the exclude
  # carves anything out. An `operations` exclude of `*/apply` — an ordinary namespaced
  # operation name, and a literal that matches nothing under the id-scope grammar —
  # canonicalized to the sentinel and denied every operation. Over-denial, and invisible
  # on any well-formed grant.
  #
  # §5.4 says outright that the rule *"does NOT reach `operations` or `peers` `[MUST]`"*,
  # and it does NOT leave the id-scope dimensions unprotected by oversight: under the
  # id-scope grammar every non-`*` pattern is a literal and a literal is never
  # structurally unmatchable, so there is nothing here for this sentinel to detect. A
  # scope boundary, not an omission.
  defp exclude_unmatchable?(frame, excl) do
    Enum.any?(excl, fn p -> canonicalize(frame, p) == @never_match end)
  end

  defp matches_scope(local_peer, value, s, kind) do
    # SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
    # `if dimension_type == "system/capability/path-scope"`, and §5.4 scopes its own
    # invalid-capability rule the same way. `kind` already names the dimension here, so
    # the scoping costs one term and cannot be got wrong by a new call site.
    if kind == :path and exclude_unmatchable?(local_peer, s.excl) do
      false
    else
      do_matches_scope(local_peer, value, s, kind)
    end
  end

  defp do_matches_scope(local_peer, value, s, kind) do
    covered =
      case kind do
        :id ->
          fn pats -> Enum.any?(pats, fn p -> matches_id_pattern(value, p) end) end

        :path ->
          cv = canonicalize(local_peer, value)
          fn pats -> Enum.any?(pats, fn p -> matches_pattern(cv, canonicalize(local_peer, p)) end) end
      end

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
  # The grant-exclude sentinel here is UNGUARDED ON PURPOSE, unlike `matches_scope`'s
  # (0.8.2.24): `s` is ALWAYS the RESOURCES dimension, which §5.2 fixes as path-scope,
  # so the type test that call site performs would be a constant here. The
  # single-dimension signature is what makes that checkable — a granter frame reaching
  # an id-scope call site is the defect, and this function cannot be one.
  defp check_resource_scope(local_peer, granter_peer, resource, s) do
    targets = text_list(Model.map_get(resource, "targets"))
    caller_excl = text_list(Model.map_get(resource, "exclude"))
    covered_local = fn pats, v -> Enum.any?(pats, fn p -> matches_pattern(v, canonicalize(local_peer, p)) end) end
    covered_grant = fn pats, v -> Enum.any?(pats, fn p -> matches_pattern(v, canonicalize(granter_peer, p)) end) end

    targets != [] and
      # An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
      # target: the coverage test below is correct in isolation and is simply never
      # reached on a sentinel, because matches_pattern answers false.
      not exclude_unmatchable?(granter_peer, s.excl) and
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
      matches_scope(local_peer, operation, g.operations, :id) and
        matches_scope(local_peer, handler_pattern, g.handlers, :path) and
        (let_peers = g.peers || %{incl: [local_peer], excl: []}
         matches_scope(local_peer, target_peer, let_peers, :id)) and
        (case resource do
           nil -> true
           r -> check_resource_scope(local_peer, granter_peer, r, g.resources)
         end)
    end

    if Enum.any?(grants_of_token(token), grant_ok), do: :allow, else: :deny
  end

  # ── §3.3 effective targets + §6.3 handler-level path check ────────────────

  @doc """
  §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
  entries from `resource.targets` BEFORE anything else looks at the request.

  The survivors are returned in the caller's OWN SPELLING, not canonicalized —
  0.8.2.21 is explicit that `effective_targets` yields raw survivors, and the
  distinction is load-bearing because the value flows on to the tree lookup, which
  canonicalizes for itself.

  Returns `nil` when the EXECUTE carries no `resource` at all, which is a different
  input from "a resource whose every target was excluded" — and for a resource-OPTIONAL
  operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with different answers, not
  merely different inputs to one disposition.

  `nil`-vs-`[]` IS THE NON-LOSSY PROJECTION §3.3 REQUIRES `[MUST]` (0.8.2.25, N11):
  *"where an implementation projects `resource.targets` onto the effective set ahead of
  the handler, that projection MUST NOT be lossy about its own emptiness — narrow when
  narrowing leaves something, and retain the raw pair when narrowing would empty it."*
  A function returning only a list cannot satisfy that: collapsing `[qA] exclude [qA]`
  to `[]` would delete the two-empties discriminator before any handler could read it,
  and the handler's refusal arm becomes dead code that only a WIRE drive can detect.
  This peer carries the discriminator as the `nil` rather than as a second return
  value — the same property, spelled the way this substrate spells "absent".

  *"Every seam that narrows is exempted alike, inbound-wire and in-process
  sub-dispatch, or one request receives two different answers according to which door
  it arrived through."* This peer has exactly ONE narrowing seam — this function,
  called by the tree handler — and §6.5's dispatch chain does not project:
  `dispatch_request` passes `exec` through untouched and `check_permission` reads
  `resource` for itself. So there is no second door to keep in step, and adding a
  projection at dispatch would create one.

  A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
  Reporting it absent would serve the WIDER absent-case answer to a request that named
  a resource, which is N11's own defect one field over.

  The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
  separately from the grant arm) and that is INHERITED here rather than restated:
  `canonicalize` answers the sentinel, `matches_pattern` then answers false, and the
  target simply survives.
  """
  @spec effective_targets(String.t(), EntityCore.Entity.t()) :: [String.t()] | nil
  def effective_targets(local_peer, exec) do
    with r when is_map(r) <- Model.field(exec, "resource"),
         true <- Map.has_key?(r, "targets") do
      targets = if is_list(Map.get(r, "targets")), do: Map.get(r, "targets"), else: []
      excl = text_list(Map.get(r, "exclude"))

      Enum.filter(targets, fn t ->
        is_binary(t) and
          not Enum.any?(excl, fn x ->
            matches_pattern(canonicalize(local_peer, t), canonicalize(local_peer, x))
          end)
      end)
    else
      _ -> nil
    end
  end

  @doc """
  §6.3's handler-level path check: may the caller access `path` AS A TREE PATH, under
  `handler_pattern`, with `token`?

  IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
  subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
  by caller-controlled input: a caller who excludes the one target its capability does
  not cover removes that target from `check_permission`'s view entirely, and a handler
  that then acts on it has authorized nothing.

  THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
  construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
  step 3, before any handler runs), and §6.3's signature names only handlers,
  operations and resources.

  THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
  rather than a choice: §6.3's block reads
  `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` — there
  is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject
  is a pattern compared against a parent's pattern; this call site compares a CONCRETE
  local path the handler is about to touch.

  Scope types: `handlers` -> path-scope, `operations` -> id-scope, `resources` ->
  path-scope. An empty `resources.include` is a legal grant shape (§5.2: handlers that
  touch no tree paths) and DENIES every path here, which is what that note says it
  should. A malformed path canonicalizes to the sentinel, which matches no grant, so it
  falls through to DENY rather than being matched against anything.
  """
  @spec check_path_permission(String.t(), String.t(), String.t(), EntityCore.Entity.t(), String.t()) ::
          boolean()
  def check_path_permission(local_peer, operation, path, token, handler_pattern) do
    Enum.any?(grants_of_token(token), fn g ->
      matches_scope(local_peer, handler_pattern, g.handlers, :path) and
        matches_scope(local_peer, operation, g.operations, :id) and
        matches_scope(local_peer, path, g.resources, :path)
    end)
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

  # scope_subset (§5.6 + §5.5a): every child include covered by parent include; child
  # inherits all parent excludes. On a PATH dimension each side canonicalizes against
  # its own per-link granter frame.
  #
  # TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
  # §3.6's id-scope grammar binds the scope TYPE, not one function — *"An
  # implementation on the canonicalizing reading is non-conformant and MUST adopt the
  # literal matcher"* — so the rule F40 landed on `matches_scope` reaches here too,
  # with delegation-chain WIDENING named as the reason: on the canonicalizing reading a
  # bare id include reads as covered by a path-form parent pattern it does not literally
  # match, and a child grant comes out wider than its parent. `lean`'s differential put
  # it at 2 of 64 include pairs and 2 of 64 exclude pairs, fail-closed, with a 16-pair
  # control alphabet reporting 0 — which is why every hand-tried example missed it.
  #
  # `kind` has NO DEFAULT and is named at every call site, because a default is how the
  # next dimension inherits the wrong matcher silently — the original F40 defect. The
  # per-link granter frames are meaningless on the id arm (an id pattern is never
  # canonicalized) and are simply unread there.
  defp scope_subset(child_peer, parent_peer, child, parent, kind) do
    frame = fn pattern, peer -> if kind == :path, do: canonicalize(peer, pattern), else: pattern end

    covers = fn pattern, value ->
      if kind == :path,
        do: matches_pattern(value, pattern),
        else: matches_id_pattern(value, pattern)
    end

    Enum.all?(child.incl, fn cp ->
      cc = frame.(cp, child_peer)
      Enum.any?(parent.incl, fn pp -> covers.(frame.(pp, parent_peer), cc) end)
    end) and
      Enum.all?(parent.excl, fn pe ->
        cpe = frame.(pe, parent_peer)
        Enum.any?(child.excl, fn ce -> covers.(frame.(ce, child_peer), cpe) end)
      end)
  end

  defp grant_subset(local_peer, child_peer, parent_peer, child, parent) do
    # §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
    # dimensions stay on the local frame. The scope KIND is a property of the DIMENSION
    # and is named at every call site, never defaulted (F50 / 0.8.2.16).
    scope_subset(local_peer, local_peer, child.handlers, parent.handlers, :path) and
      scope_subset(local_peer, local_peer, child.operations, parent.operations, :id) and
      scope_subset(child_peer, parent_peer, child.resources, parent.resources, :path) and
      (cp = child.peers || %{incl: [local_peer], excl: []}
       pp = parent.peers || %{incl: [local_peer], excl: []}
       scope_subset(local_peer, local_peer, cp, pp, :id))
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

  def verify_capability_chain(local_peer, store, capability, included),
    do: verify_capability_chain_rooted_at(local_peer, local_peer, store, capability, included)

  @doc """
  `verify_capability_chain/4` with the expected ROOT granter named separately from the
  verifying peer.

  §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted
  by the TARGET peer, so root-trust is relaxed away from the local peer — and every other
  clause (per-link signatures, grantee resolution, temporal validity, attenuation,
  caveats) is unchanged. Parameterized rather than forked because a second copy of a
  chain walk is a second copy that drifts.

  A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `root_peer`
  differs from `local_peer` the quorum arm is REFUSED outright rather than verified:
  *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
  GROUP's authority — its co-signers authorized it too. Accepting it would let any one
  signer's target confer the whole group's grant, which is E3/F66's over-acceptance.
  §5.5's M6 also requires the LOCAL peer in the signer set, so the quorum arm has no
  meaning in a foreign frame even on its own terms.
  """
  def verify_capability_chain_rooted_at(local_peer, root_peer, store, capability, included) do
    resolve_fn = resolve(included, store)

    case collect_chain(capability, resolve_fn) do
      {:error, _} ->
        :deny

      {:ok, chain} ->
        root = List.last(chain)

        # Root authority: a §3.6 M3 multi-sig root (root-only) passes k-of-n quorum
        # verification and ONLY in the local frame; a single-sig root must root at
        # `root_peer`.
        root_ok =
          case multi_granter(root) do
            %{} = mg ->
              root_peer == local_peer and
                verify_multisig_root(local_peer, resolve_fn, root, mg, included)

            nil ->
              case Model.bytes_field(root, "granter") do
                nil ->
                  false

                gh ->
                  case resolve_fn.(gh) do
                    %{} = g ->
                      case Model.bytes_field(g, "public_key") do
                        pk when is_binary(pk) -> Identity.peer_id_of_pubkey(pk) == root_peer
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

  @uint64_max 18_446_744_073_709_551_615

  # §6.2 CAP-6a (INGEST): every temporal field on a RECEIVED token must be either ABSENT
  # (legal — "no bound") or representable as primitive/uint. A bignum, a negative integer,
  # or any non-integer is MALFORMED, and the verifier MUST refuse it rather than read the
  # unrepresentable field as absent — absent means *no expiry*, so the fail-open reading
  # grants an immortal capability to whoever sent the malformed value.
  #
  # This is the reader-side half of CAP-6 and it is where this peer failed OPEN:
  # Model.uint_field/2 answers nil BOTH for an absent field and for a present-but-negative
  # one (its guard is `is_integer(n) and n >= 0`), so `expires_at: -1` skipped the expiry
  # check entirely and was honored with 200.
  #
  # Elixir integers are arbitrary-precision, so the `>2^64` half is a DELIBERATE range
  # check — there is no overflow to trip over, and a bignum language that "just does the
  # arithmetic" silently never notices.
  defp temporal_fields_representable(cap) do
    Enum.all?(["expires_at", "not_before", "created_at"], fn key ->
      case Model.field(cap, key) do
        nil -> true
        v when is_integer(v) -> v >= 0 and v <= @uint64_max
        _ -> false
      end
    end)
  end

  # MUST run BEFORE the range checks below — they are exactly what the
  # absent-vs-unrepresentable ambiguity defeats.
  defp temporal_ok(current, t) do
    if not temporal_fields_representable(current) do
      false
    else
      temporal_range_ok(current, t)
    end
  end

  defp temporal_range_ok(current, t) do
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

  # ── §1.4 PD-2: outbound sub-dispatch authorization ─────────────────────────

  @doc """
  Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.

  §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree` and
  `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's handler
  pattern to be the target uri's peer-relative path, because a grant names HANDLERS and a
  handler pattern never carries a peer segment. Matching a grant against the absolute or
  schemed form matches nothing, silently, which reads at the wire as an authority refusal.

  The first segment is dropped ONLY when it is a peer_id. A peer-relative
  `system/protocol/connect` must not lose `system` — the standing defect on `smalltalk`
  and `forth`, where an unconditional strip made every self-minted grant unusable while
  the handshake stayed green.
  """
  def peer_relative_of(uri) do
    p = normalize_uri(uri)

    if String.starts_with?(p, "/") do
      body = String.slice(p, 1..-1//1)

      case String.split(body, "/", parts: 2) do
        [first, rest] -> if is_peer_id(first), do: rest, else: body
        [only] -> if is_peer_id(only), do: "", else: only
      end
    else
      p
    end
  end

  @doc """
  Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
  tolerant of the pattern arriving absolute or peer-relative.

  §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while the
  grant path is built from the PEER-RELATIVE one. The two are one segment apart and
  concatenating the wrong one yields a doubled peer segment whose lookup misses — which
  fails closed as "no handler grant" and is indistinguishable, at the wire, from a
  genuine authority refusal.
  """
  def grant_path_for(local_peer, pattern) do
    prefix = "/" <> local_peer <> "/"

    rel =
      if String.starts_with?(pattern, prefix),
        do: String.replace_prefix(pattern, prefix, ""),
        else: pattern

    "/" <> local_peer <> "/system/capability/grants/" <> rel
  end

  @doc """
  Verify a presented reentry credential against §1.4's clauses and, where they all hold,
  answer the `peers` scope Dimension 4 relaxes to. `nil` relaxes nothing.

  Every clause is required and failing any relaxes nothing: the chain ROOT granter
  resolves to the TARGET peer and is NOT a multi-signature root (a K-of-N root is a
  GROUP's authority and never relaxes Dimension 4 — `verify_capability_chain_rooted_at/5`
  refuses the quorum arm in a foreign frame, which is where that rule lands); the LEAF
  grantee is the local peer; the chain is valid and not revoked.
  """
  def target_minted_peers_relaxation(local_peer, target_peer, store, cred, included) do
    # Nothing to relax — the default already covers this peer. Treating a self-targeted
    # credential as a relaxation would make the exemption reachable with no foreign mint
    # at all.
    if target_peer == local_peer do
      nil
    else
      with :allow <-
             verify_capability_chain_rooted_at(local_peer, target_peer, store, cred, included),
           false <- is_revoked(local_peer, store, cred, included),
           gh when is_binary(gh) <- Model.bytes_field(cred, "grantee"),
           %{} = ge <- resolve(included, store).(gh),
           pk when is_binary(pk) <- Model.bytes_field(ge, "public_key"),
           true <- Identity.peer_id_of_pubkey(pk) == local_peer do
        # The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent means
        # the granter — the target peer — which is the ordinary reentry shape: "you may
        # dispatch back to me".
        case grants_of_token(cred) do
          [g | _] -> g.peers || %{incl: [target_peer], excl: []}
          [] -> nil
        end
      else
        _ -> nil
      end
    end
  end

  @doc """
  §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
  LEAVES the peer, with all four dimensions applied.

  ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides
  all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern the
  target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER naming
  this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4.

  *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT a
  grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
  sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
  BYPASS it is distinguished from is a peer that treats the credential as a standalone
  authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
  obvious vectors agree under either reading (sources agree -> allow, no source ->
  refuse), so the only input that separates them is a VALID credential presented to a
  handler whose own grant does NOT cover the request, which MUST refuse.

  A credential failing any verification clause relaxes NOTHING and the handler grant gates
  unrelaxed — it does not turn the verdict into an error.

  `target_peer` is supplied by the caller rather than derived here: on the §6.11 reentry
  seam the uri may be PEER-RELATIVE and the destination is the connection's remote, so
  `extract_peer(uri, local)` would answer the LOCAL peer and Dimension 4 would pass
  vacuously on the default `{include: [local]}` — the exemption would then never be
  exercised and a bypass would read as a compose.

  `cred == nil` is the ambient arm: Dimension 4 is decided by the handler's grant alone.
  """
  def check_outbound_sub_dispatch(
        local_peer,
        target_peer,
        handler_pattern,
        operation,
        store,
        handler_grant,
        resource,
        cred,
        included
      ) do
    # Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
    relax_to =
      if cred,
        do: target_minted_peers_relaxation(local_peer, target_peer, store, cred, included),
        else: nil

    Enum.any?(grants_of_token(handler_grant), fn g ->
      matches_scope(local_peer, handler_pattern, g.handlers, :path) and
        matches_scope(local_peer, operation, g.operations, :id) and
        check_resource_scope(local_peer, local_peer, resource, g.resources) and
        # Dimension 4. §5.2's default for an absent `peers` scope is
        # {include: [local_peer_id]}, so a foreign target fails unless this grant names it
        # or a target-minted credential relaxes it.
        (matches_scope(local_peer, target_peer, g.peers || %{incl: [local_peer], excl: []}, :id) or
           (relax_to != nil and matches_scope(local_peer, target_peer, relax_to, :id)))
    end)
  end
end
