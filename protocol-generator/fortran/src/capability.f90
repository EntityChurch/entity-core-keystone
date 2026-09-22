! entity-core-protocol-fortran — src/capability.f90 (L3: the §5 verification core).
!
! Pattern matching (§5.4), request verification (§5.2), delegation-chain verification
! (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1), and §3.6 M3 multi-sig
! K-of-N — ported from the §5 pseudocode (the Rexx capability.rex / Tcl ::capability::
! shapes) onto Fortran's ecf_value_t / entity_t model.
!
! Layer-1 verdict is ALLOW / DENY (§5.10); the three-way request verdict folds in the
! §4.10(b) structural CHAIN_TOO_DEEP (-> 400, NOT 403 — structural excess is not an authz
! denial) and the §5.5 unresolvable-grantee carve-out (-> 401). Verdicts are integer
! codes (the status-code error model); no fixed-width trap on thresholds/temporal bounds
! (ms timestamps are ~1.7e12, far below 2^63, so a plain signed compare is exact).
!
! §PR-8 granter-frame: the RESOURCE dimension canonicalizes against the GRANTER's peer_id;
! handlers/operations/peers stay local. For the self-issued dominant path (granter=local)
! this is byte-identical.
module entity_core_capability
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor, only : ecf_value_t, EV_MAP, EV_ARRAY, EV_ABSENT, EV_BYTES, EV_UINT
  use entity_core_val
  use entity_core_ent
  use entity_core_store
  use entity_core_identity
  use entity_core_wire
  use entity_core_net, only : now_ms
  implicit none
  private

  integer, parameter, public :: MAX_CHAIN_DEPTH = 64        ! §4.10(b)

  ! request verdicts
  integer, parameter, public :: CV_ALLOW = 0, CV_AUTHN_FAIL = 1, CV_AUTHZ_DENY = 2, &
                                CV_CHAIN_TOO_DEEP = 3

  ! The unmatchable value (0.8.2.20). Unreachable as a canonical path by CONSTRUCTION:
  ! its first segment cannot be a peer_id, since cap_is_peer_id requires >= 46 Base58
  ! characters and '-' is outside the Base58 alphabet.
  character(len=*), parameter :: never_match = '/never-match'

  public :: cap_now_ms, cap_grant, cap_canonicalize, cap_normalize_uri
  public :: cap_matches_pattern, cap_matches_id_pattern, cap_matches_scope, cap_is_peer_id, cap_extract_peer
  public :: cap_check_permission, cap_resolve, cap_find_signature
  public :: cap_temporal_fields_representable, cap_add_ttl
  public :: cap_resolve_granter_peer_id, cap_grants_of_token, cap_grant_subset_local
  public :: cap_chain_exceeds_depth, cap_verify_chain, cap_is_revoked, cap_verify_request
  public :: cap_effective_targets, cap_check_path_permission

contains

  integer(int64) function cap_now_ms()
    cap_now_ms = now_ms()
  end function cap_now_ms

  ! ── string prefix/suffix ──
  logical function starts_with(s, p)
    character(len=*), intent(in) :: s, p
    if (len(p) == 0) then; starts_with = .true.; return; end if
    if (len(s) < len(p)) then; starts_with = .false.; return; end if
    starts_with = (s(1:len(p)) == p)
  end function starts_with

  logical function ends_with(s, p)
    character(len=*), intent(in) :: s, p
    if (len(p) == 0) then; ends_with = .true.; return; end if
    if (len(s) < len(p)) then; ends_with = .false.; return; end if
    ends_with = (s(len(s)-len(p)+1:) == p)
  end function ends_with

  ! ── §4.4 grant builder: handlers/resources/operations [+ peers] scope map ──
  ! peers omitted when peers_words is '' (a single blank).
  function cap_grant(handlers, resources, operations, peers) result(g)
    character(len=*), intent(in) :: handlers, resources, operations, peers
    type(ecf_value_t) :: g
    g = v_map_empty()
    g = v_map_put(g, 'handlers', v_scope(handlers))
    g = v_map_put(g, 'resources', v_scope(resources))
    g = v_map_put(g, 'operations', v_scope(operations))
    if (len_trim(peers) > 0) g = v_map_put(g, 'peers', v_scope(peers))
  end function cap_grant

  ! ── §5.4 pattern matching ──
  function cap_normalize_uri(uri) result(r)
    character(len=*), intent(in) :: uri
    character(len=:), allocatable :: r
    if (starts_with(uri, 'entity://')) then
      r = '/' // uri(10:)
    else
      r = uri
    end if
  end function cap_normalize_uri

  ! canonicalize a path against the local peer; `invalid` set on a reserved-relative or
  ! ambiguous-bare-wildcard path (mapped to 400 at the dispatch top).
  subroutine cap_canonicalize(local, path, out, invalid)
    character(len=*),              intent(in)  :: local, path
    character(len=:), allocatable, intent(out) :: out
    logical,                       intent(out) :: invalid
    invalid = .false.
    if (starts_with(path, './') .or. starts_with(path, '../')) then; invalid = .true.; out = path; return; end if
    if (starts_with(path, '*/')) then; invalid = .true.; out = path; return; end if
    if (starts_with(path, '/')) then; out = path; return; end if
    out = '/' // trim(local) // '/' // path
  end subroutine cap_canonicalize

  ! canon -- cap_canonicalize FOR THE MATCHERS, which have no error channel.
  ! TOTAL (0.8.2.20): the result is 'a canonical path OR never_match'.
  !
  ! cap_canonicalize itself keeps its `invalid` flag, because the dispatch top uses it
  ! as a 400 and is exactly the caller 0.8.2.20 says SHOULD have the diagnostic. The
  ! defect was HERE: this wrapper IGNORED `invalid` and returned the input unchanged,
  ! which matched nothing -- the desired outcome in an INCLUDE and the opposite of it
  ! in an EXCLUDE, so a grant exclude carrying '../x' carved out nothing and the grant
  ! was silently wider than its author wrote (measured on the wire 2026-09-14).
  function canon(local, path) result(out)
    character(len=*), intent(in) :: local, path
    character(len=:), allocatable :: out
    logical :: inv
    call cap_canonicalize(local, path, out, inv)
    if (inv) out = never_match
  end function canon

  ! AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
  ! in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
  ! exclude (carves out nothing), so the reading is chosen where the POSITION is known
  ! and cap_matches_pattern stays uniform over its operands. The guard sits outside the
  ! scope-type dispatch, transcribing 5.2s loop literally.
  logical function exclude_unmatchable(frame, excl)
    character(len=*), intent(in) :: frame
    type(str_t),      intent(in) :: excl(:)
    integer :: i
    exclude_unmatchable = .false.
    do i = 1, size(excl)
      if (canon(frame, excl(i)%s) == never_match) then
        exclude_unmatchable = .true.; return
      end if
    end do
  end function exclude_unmatchable

  recursive function cap_matches_pattern(path, pattern) result(m)
    character(len=*), intent(in) :: path, pattern
    logical :: m
    integer :: i
    ! never_match never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    ! rule rather than a property of the string: the line below returns .true. for a
    ! bare '*', so safety must not rest on a value merely looking unmatchable.
    if (path == never_match .or. pattern == never_match) then; m = .false.; return; end if
    if (pattern == '*') then; m = .true.; return; end if
    if (starts_with(pattern, '/*/')) then
      if (len(path) == 0) then; m = .false.; return; end if
      i = index(path(2:), '/')
      if (i == 0) then; m = .false.; return; end if
      i = i + 1                                   ! position of '/' at/after index 2
      m = cap_matches_pattern(path(i+1:), pattern(4:))
      return
    end if
    if (len(pattern) >= 2 .and. ends_with(pattern, '/*')) then
      m = starts_with(path, pattern(1:len(pattern)-1))
      return
    end if
    m = (path == pattern)
  end function cap_matches_pattern

  ! is canonicalized value cv covered by any pattern in `pats` (canonicalized in `frame`)?
  logical function covered(frame, pats, cv)
    character(len=*), intent(in) :: frame, cv
    type(str_t),      intent(in) :: pats(:)
    integer :: i
    covered = .false.
    do i = 1, size(pats)
      if (cap_matches_pattern(cv, canon(frame, pats(i)%s))) then; covered = .true.; return; end if
    end do
  end function covered

  ! §5.2 id-scope match (0.8.1, F40) — operations and peers. Literal comparison with
  ! exactly two wildcard forms: bare '*' and a trailing slash-star segment-prefix. None
  ! of the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
  ! literal string: a non-match, never a fault.
  logical function cap_matches_id_pattern(value, pattern) result(m)
    character(len=*), intent(in) :: value, pattern
    integer :: plen
    if (pattern == '*') then; m = .true.; return; end if
    plen = len(pattern)
    if (plen >= 2 .and. pattern(plen-1:plen) == '/*') then
      m = (len(value) >= plen-1)
      if (m) m = (value(1:plen-1) == pattern(1:plen-1))
      return
    end if
    m = (value == pattern)
  end function cap_matches_id_pattern

  ! is `value` covered by any id-scope pattern in `pats`? (no canonicalization)
  logical function covered_id(pats, value)
    character(len=*), intent(in) :: value
    type(str_t),      intent(in) :: pats(:)
    integer :: i
    covered_id = .false.
    do i = 1, size(pats)
      if (cap_matches_id_pattern(value, pats(i)%s)) then; covered_id = .true.; return; end if
    end do
  end function covered_id

  ! §5.2 typed scope match. `kind` is 'id' (operations, peers) or 'path' (handlers,
  ! resources) and is given at every call site — there is no default, so a new one
  ! cannot inherit the wrong matcher silently, which is exactly the F40 defect.
  logical function cap_matches_scope(local, value, scope, kind)
    character(len=*),  intent(in) :: local, value, kind
    type(ecf_value_t), intent(in) :: scope
    character(len=:), allocatable :: cv
    type(str_t), allocatable :: incl(:), excl(:)
    incl = text_list(m_array(scope, 'include'))
    excl = text_list(m_array(scope, 'exclude'))
    if (exclude_unmatchable(local, excl)) then       ! 0.8.2.21 -- deny
      cap_matches_scope = .false.; return
    end if
    if (kind == 'id') then
      if (.not. covered_id(incl, value)) then; cap_matches_scope = .false.; return; end if
      cap_matches_scope = .not. covered_id(excl, value)
      return
    end if
    cv = canon(local, value)
    if (.not. covered(local, incl, cv)) then; cap_matches_scope = .false.; return; end if
    cap_matches_scope = .not. covered(local, excl, cv)
  end function cap_matches_scope

  ! ── §5.2 check-permission ──
  function first_segment(uri) result(seg)
    character(len=*), intent(in) :: uri
    character(len=:), allocatable :: seg, u
    integer :: i
    if (starts_with(uri, '/')) then; u = uri(2:); else; u = uri; end if
    i = index(u, '/')
    if (i > 0) then; seg = u(1:i-1); else; seg = u; end if
  end function first_segment

  logical function cap_is_peer_id(seg)
    character(len=*), intent(in) :: seg
    character(len=*), parameter :: B58 = &
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    integer :: i
    cap_is_peer_id = .false.
    if (len(seg) < 46) return
    do i = 1, len(seg)
      if (index(B58, seg(i:i)) == 0) return
    end do
    cap_is_peer_id = .true.
  end function cap_is_peer_id

  function cap_extract_peer(local, uri) result(p)
    character(len=*), intent(in) :: local, uri
    character(len=:), allocatable :: p, first
    first = first_segment(cap_normalize_uri(uri))
    if (cap_is_peer_id(first)) then; p = first; else; p = local; end if
  end function cap_extract_peer

  logical function check_resource_scope(local, granter_peer, resource, scope)
    character(len=*),  intent(in) :: local, granter_peer
    type(ecf_value_t), intent(in) :: resource, scope
    type(str_t), allocatable :: targets(:), caller_excl(:), incl(:), excl(:)
    character(len=:), allocatable :: ct
    integer :: i
    check_resource_scope = .false.
    targets = text_list(m_array(resource, 'targets'))
    caller_excl = text_list(m_array(resource, 'exclude'))
    incl = text_list(m_array(scope, 'include'))
    excl = text_list(m_array(scope, 'exclude'))
    if (size(targets) == 0) return
    ! An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    ! target: the coverage test below is correct in isolation and is simply never
    ! reached on a sentinel, because cap_matches_pattern answers .false.
    if (exclude_unmatchable(granter_peer, excl)) return
    do i = 1, size(targets)
      ct = canon(local, targets(i)%s)
      if (size(caller_excl) > 0) then
        if (covered(local, caller_excl, ct)) cycle
      end if
      if (.not. covered(granter_peer, incl, ct)) return
      if (covered(granter_peer, excl, ct)) return
    end do
    check_resource_scope = .true.
  end function check_resource_scope

  ! ── §5.2 effective targets and §6.3 check_path_permission (0.8.2.20/.21/.25) ──

  ! §5.2's effective target list: the caller's OWN `resource.exclude` removes entries
  ! from the request BEFORE anything else looks at it.
  !
  ! Survivors come back in the CALLER'S OWN SPELLING, never canonicalized. 0.8.2.21 is
  ! explicit that `effective_targets` yields raw survivors, and it is load-bearing here
  ! because the value flows on to cap_canonicalize, which frames for itself.
  !
  ! `has_resource` IS THE SECOND HALF OF A NON-LOSSY PROJECTION [MUST] (§3.3, 0.8.2.25
  ! N11): "where an implementation projects resource.targets onto the effective set
  ! ahead of the handler, that projection MUST NOT be lossy about its own emptiness."
  ! An ABSENT resource and a resource whose every target the caller excluded are
  ! DIFFERENT REQUESTS for a resource-OPTIONAL operation. A routine returning only the
  ! survivor list collapses `[qA] exclude [qA]` to the same `[]` an absent resource
  ! gives, which deletes the discriminator before any handler can read it and turns the
  ! handler's refusal arm into dead code only a WIRE drive can detect. Returning the
  ! flag beside the survivors keeps the two apart by construction.
  !
  ! THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN, and that asymmetry is
  ! deliberate: §5.4's table rules the caller arm separately from the GRANT arm, which
  ! denies (see exclude_unmatchable in check_resource_scope). Here `canon` answers the
  ! never_match sentinel, cap_matches_pattern then answers .false., and the target simply
  ! survives -- inherited from the matcher rather than restated.
  !
  ! ONE NARROWING SEAM. This is the only place in this peer where resource.targets is
  ! reduced to a subject; §6.5's dispatch chain does not project (check_resource_scope
  ! iterates every target and cycles the excluded ones without selecting one). A second
  ! narrowing site would be a second thing that can disagree with this one, and §6.3
  ! cannot close a gap between two derivations of its own subject.
  subroutine cap_effective_targets(local, exec, eff, has_resource)
    character(len=*), intent(in)  :: local
    type(entity_t),   intent(in)  :: exec
    type(str_t), allocatable, intent(out) :: eff(:)
    logical,          intent(out) :: has_resource
    type(ecf_value_t) :: r
    type(str_t), allocatable :: targets(:), caller_excl(:)
    logical, allocatable :: keep(:)
    character(len=:), allocatable :: ct
    integer :: i, n
    has_resource = .false.
    allocate(eff(0))
    r = ent_map_field(exec, 'resource')
    if (r%vkind /= EV_MAP) return
    if (.not. m_has(r, 'targets')) return
    has_resource = .true.
    targets = text_list(m_array(r, 'targets'))
    caller_excl = text_list(m_array(r, 'exclude'))
    if (size(targets) == 0) return
    allocate(keep(size(targets)))
    n = 0
    do i = 1, size(targets)
      ct = canon(local, targets(i)%s)
      keep(i) = .not. covered(local, caller_excl, ct)
      if (keep(i)) n = n + 1
    end do
    deallocate(eff); allocate(eff(n))
    n = 0
    do i = 1, size(targets)
      if (.not. keep(i)) cycle
      n = n + 1
      eff(n) = targets(i)
    end do
  end subroutine cap_effective_targets

  ! §6.3's handler-level path check.
  !
  ! IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the sole enforcement wherever the
  ! subject is derived AFTER dispatch, and the dispatch-level check can be made VACUOUS by
  ! caller-controlled input: a caller who excludes the one target its capability does not
  ! cover removes that target from check_resource_scope's view entirely -- it `cycle`s --
  ! and a handler that then acts on it has authorized nothing.
  !
  ! THREE DIMENSIONS, NOT FOUR. `peers` is not consulted: the path is local by construction
  ! at this point (§1.4's inbound rule refuses a foreign namespace at §6.5 step 3, above the
  ! verdict), and §6.3's signature names only handlers, operations and resources.
  !
  ! THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is §6.3's own signature rather
  ! than a choice: its block reads matches_scope(canonical_path, grant.resources,
  ! "path-scope", local_peer_id) -- there is no granter parameter to pass. §5.5a governs
  ! chain ATTENUATION, where the subject is a pattern compared against a parent's pattern;
  ! this call site compares a CONCRETE local path the handler is about to touch. Threading
  ! the per-link granter frame in here by analogy with §5.5a is a recorded cohort error.
  !
  ! There is no caller-exclude set at this call site: the subject is a single concrete path
  ! and the caller's own exclusions were applied in deriving it. So every GRANT exclude
  ! covering the subject denies -- which cap_matches_scope already implements, including
  ! 0.8.2.21's sentinel rule, making this three calls to it and nothing else.
  logical function cap_check_path_permission(local, operation, path, token, handler_pattern)
    character(len=*), intent(in) :: local, operation, path, handler_pattern
    type(entity_t),   intent(in) :: token
    type(ecf_value_t) :: garr, g
    character(len=:), allocatable :: cp
    integer :: i, n
    logical :: invalid
    cap_check_path_permission = .false.
    ! cap_canonicalize is total and may answer the never_match sentinel, which matches no
    ! grant (§5.4) -- so a malformed path falls through to DENY rather than being compared.
    call cap_canonicalize(local, path, cp, invalid)
    garr = cap_grants_of_token(token)
    n = arr_count(garr)
    do i = 1, n
      g = arr_item(garr, i)
      if (.not. cap_matches_scope(local, handler_pattern, m_submap(g, 'handlers'), 'path')) cycle
      if (.not. cap_matches_scope(local, operation, m_submap(g, 'operations'), 'id')) cycle
      if (.not. cap_matches_scope(local, cp, m_submap(g, 'resources'), 'path')) cycle
      cap_check_path_permission = .true.; return
    end do
  end function cap_check_path_permission

  ! §PR-8: the granter's peer_id frames a cap's resource patterns.
  function cap_resolve_granter_peer_id(inc, store, cap) result(pid)
    type(entity_t), intent(in) :: inc(:)
    type(store_t),  intent(in) :: store
    type(entity_t), intent(in) :: cap
    character(len=:), allocatable :: pid
    type(entity_t) :: g
    integer(int8), allocatable :: gh(:), pk(:)
    pid = ''
    gh = ent_bytes(cap, 'granter')
    if (size(gh) == 0) return
    g = cap_resolve(inc, store, gh)
    if (.not. g%present) return
    pk = ent_bytes(g, 'public_key')
    if (size(pk) == 0) return
    pid = peer_id_of_pubkey(pk)
  end function cap_resolve_granter_peer_id

  ! the grants array value of a token entity.
  function cap_grants_of_token(token) result(g)
    type(entity_t), intent(in) :: token
    type(ecf_value_t) :: g
    g = m_array(ent_data_map(token), 'grants')
  end function cap_grants_of_token

  logical function cap_check_permission(local, granter_peer, exec, token, handler_pattern)
    character(len=*), intent(in) :: local, granter_peer, handler_pattern
    type(entity_t),   intent(in) :: exec, token
    character(len=:), allocatable :: operation, uri, target_peer
    type(ecf_value_t) :: resource, garr, g, peers
    integer :: i, n
    logical :: ok
    cap_check_permission = .false.
    operation = ent_text(exec, 'operation')
    uri = ent_text(exec, 'uri')
    target_peer = cap_extract_peer(local, uri)
    resource = ent_map_field(exec, 'resource')
    garr = cap_grants_of_token(token)
    n = arr_count(garr)
    do i = 1, n
      g = arr_item(garr, i)
      ok = cap_matches_scope(local, operation, m_submap(g, 'operations'), 'id') .and. &
           cap_matches_scope(local, handler_pattern, m_submap(g, 'handlers'), 'path')
      if (ok) then
        peers = m_submap(g, 'peers')
        if (peers%vkind /= EV_MAP) then
          ok = (target_peer == local)          ! absent peers -> {local}
        else
          ok = cap_matches_scope(local, target_peer, peers, 'id')
        end if
      end if
      if (ok .and. resource%vkind == EV_MAP) &
        ok = check_resource_scope(local, granter_peer, resource, m_submap(g, 'resources'))
      if (ok) then; cap_check_permission = .true.; return; end if
    end do
  end function cap_check_permission

  ! ── §5.5 chain helpers ──
  function cap_resolve(inc, store, h) result(e)
    type(entity_t), intent(in) :: inc(:)
    type(store_t),  intent(in) :: store
    integer(int8),  intent(in) :: h(:)
    type(entity_t) :: e
    integer :: i
    e%present = .false.
    if (size(h) == 0) return
    do i = 1, size(inc)
      if (hash_eq(ent_hash(inc(i)), h)) then; e = inc(i); return; end if
    end do
    e = store_get_by_hash(store, h)
  end function cap_resolve

  function cap_find_signature(target, inc) result(e)
    integer(int8), intent(in) :: target(:)
    type(entity_t), intent(in) :: inc(:)
    type(entity_t) :: e
    integer :: i
    e%present = .false.
    if (size(target) == 0) return
    do i = 1, size(inc)
      if (ent_type(inc(i)) == 'system/signature') then
        if (hash_eq(ent_bytes(inc(i), 'target'), target)) then; e = inc(i); return; end if
      end if
    end do
  end function cap_find_signature

  ! §4.10(b) structural pre-check: .true. iff the chain exceeds MAX depth. Walks parent
  ! pointers WITHOUT verifying sigs — an unreachable parent is NOT a depth problem (stays
  ! 403 in the authz walk), so this maps ONLY genuine over-depth -> 400 chain_depth_exceeded.
  logical function cap_chain_exceeds_depth(store, cap, inc)
    type(store_t),  intent(in) :: store
    type(entity_t), intent(in) :: cap
    type(entity_t), intent(in) :: inc(:)
    type(entity_t) :: current, parent
    integer(int8), allocatable :: ph(:)
    integer :: depth
    current = cap; depth = 0
    do
      if (depth > MAX_CHAIN_DEPTH) then; cap_chain_exceeds_depth = .true.; return; end if
      ph = ent_bytes(current, 'parent')
      if (size(ph) == 0) then; cap_chain_exceeds_depth = .false.; return; end if
      parent = cap_resolve(inc, store, ph)
      if (.not. parent%present) then; cap_chain_exceeds_depth = .false.; return; end if
      current = parent; depth = depth + 1
    end do
  end function cap_chain_exceeds_depth

  ! collect the cap..root parent chain into `chain` (1=cap ... n=root); ok=.false. on a
  ! broken/over-deep chain.
  subroutine collect_chain(cap, inc, store, chain, ok)
    type(entity_t),              intent(in)  :: cap
    type(entity_t),              intent(in)  :: inc(:)
    type(store_t),               intent(in)  :: store
    type(entity_t), allocatable, intent(out) :: chain(:)
    logical,                     intent(out) :: ok
    type(entity_t), allocatable :: tmp(:)
    type(entity_t) :: current, parent
    integer(int8), allocatable :: ph(:)
    integer :: depth
    allocate(chain(0))
    current = cap; depth = 0
    do
      if (depth > MAX_CHAIN_DEPTH) then; ok = .false.; return; end if
      allocate(tmp(size(chain) + 1))
      if (size(chain) > 0) tmp(1:size(chain)) = chain
      tmp(size(tmp)) = current
      call move_alloc(tmp, chain)
      ph = ent_bytes(current, 'parent')
      if (size(ph) == 0) then; ok = .true.; return; end if
      parent = cap_resolve(inc, store, ph)
      if (.not. parent%present) then; ok = .false.; return; end if
      current = parent; depth = depth + 1
    end do
  end subroutine collect_chain

  ! §PR-8 per-link frame = the cap's granter peer_id (root/no-granter -> local; single-sig
  ! unresolvable -> '').
  function link_granter_peer(inc, store, local, cap) result(p)
    type(entity_t), intent(in) :: inc(:)
    type(store_t),  intent(in) :: store
    character(len=*), intent(in) :: local
    type(entity_t), intent(in) :: cap
    character(len=:), allocatable :: p
    type(entity_t) :: g
    integer(int8), allocatable :: gh(:), pk(:)
    gh = ent_bytes(cap, 'granter')
    if (size(gh) == 0) then; p = local; return; end if
    g = cap_resolve(inc, store, gh)
    if (.not. g%present) then; p = ''; return; end if
    pk = ent_bytes(g, 'public_key')
    if (size(pk) == 0) then; p = ''; return; end if
    p = peer_id_of_pubkey(pk)
  end function link_granter_peer

  logical function scope_subset(child_peer, parent_peer, child, parent)
    character(len=*),  intent(in) :: child_peer, parent_peer
    type(ecf_value_t), intent(in) :: child, parent
    type(str_t), allocatable :: ci(:), pin(:), pex(:), cex(:)
    character(len=:), allocatable :: cc, cpe
    integer :: i, j
    logical :: cov
    scope_subset = .false.
    ci  = text_list(m_array(child,  'include'))
    pin = text_list(m_array(parent, 'include'))
    do i = 1, size(ci)
      cc = canon(child_peer, ci(i)%s)
      cov = .false.
      do j = 1, size(pin)
        if (cap_matches_pattern(cc, canon(parent_peer, pin(j)%s))) then; cov = .true.; exit; end if
      end do
      if (.not. cov) return
    end do
    pex = text_list(m_array(parent, 'exclude'))
    cex = text_list(m_array(child,  'exclude'))
    do i = 1, size(pex)
      cpe = canon(parent_peer, pex(i)%s)
      cov = .false.
      do j = 1, size(cex)
        if (cap_matches_pattern(cpe, canon(child_peer, cex(j)%s))) then; cov = .true.; exit; end if
      end do
      if (.not. cov) return
    end do
    scope_subset = .true.
  end function scope_subset

  logical function grant_subset(local, child_peer, parent_peer, child, parent)
    character(len=*),  intent(in) :: local, child_peer, parent_peer
    type(ecf_value_t), intent(in) :: child, parent
    type(ecf_value_t) :: cp, pp
    grant_subset = .false.
    if (.not. scope_subset(local, local, m_submap(child, 'handlers'),   m_submap(parent, 'handlers'))) return
    if (.not. scope_subset(local, local, m_submap(child, 'operations'), m_submap(parent, 'operations'))) return
    if (.not. scope_subset(child_peer, parent_peer, m_submap(child, 'resources'), m_submap(parent, 'resources'))) return
    cp = m_submap(child, 'peers');  if (cp%vkind /= EV_MAP) cp = v_scope(local)
    pp = m_submap(parent, 'peers'); if (pp%vkind /= EV_MAP) pp = v_scope(local)
    grant_subset = scope_subset(local, local, cp, pp)
  end function grant_subset

  ! public wrapper: is grant `child` a subset of grant `parent` in the local frame
  ! (§4.4/§5.4 bounded-mint check — the dispatch-site cap:request/delegate bound).
  logical function cap_grant_subset_local(local, child, parent)
    character(len=*),  intent(in) :: local
    type(ecf_value_t), intent(in) :: child, parent
    cap_grant_subset_local = grant_subset(local, local, local, child, parent)
  end function cap_grant_subset_local

  logical function is_attenuated(local, child_peer, parent_peer, child, parent)
    character(len=*), intent(in) :: local, child_peer, parent_peer
    type(entity_t),   intent(in) :: child, parent
    type(ecf_value_t) :: cg, pg, c, p
    integer :: i, j
    integer(int64) :: pe, ce
    logical :: pep, cep, ok
    is_attenuated = .false.
    cg = cap_grants_of_token(child)
    pg = cap_grants_of_token(parent)
    do i = 1, arr_count(cg)
      c = arr_item(cg, i)
      ok = .false.
      do j = 1, arr_count(pg)
        p = arr_item(pg, j)
        if (grant_subset(local, child_peer, parent_peer, c, p)) then; ok = .true.; exit; end if
      end do
      if (.not. ok) return
    end do
    call ent_uint(parent, 'expires_at', pe, pep)
    call ent_uint(child,  'expires_at', ce, cep)
    if (pep .and. .not. cep) return
    if (pep) then; is_attenuated = (ce <= pe); else; is_attenuated = .true.; end if
  end function is_attenuated

  logical function check_delegation_caveats(parent, child, depth)
    type(entity_t), intent(in) :: parent, child
    integer,        intent(in) :: depth
    type(ecf_value_t) :: caveats
    integer(int64) :: mdd, maxttl, ex, cr
    logical :: p1, p2, p3, p4, depth_ok, ttl_ok
    check_delegation_caveats = .true.
    caveats = ent_map_field(parent, 'delegation_caveats')
    if (caveats%vkind /= EV_MAP) return
    if (m_bool(caveats, 'no_delegation')) then; check_delegation_caveats = .false.; return; end if
    depth_ok = .true.; ttl_ok = .true.
    call m_uint(caveats, 'max_delegation_depth', mdd, p1)
    if (p1) depth_ok = (int(depth, int64) < mdd)
    call m_uint(caveats, 'max_delegation_ttl', maxttl, p2)
    if (p2) then
      call ent_uint(child, 'expires_at', ex, p3)
      call ent_uint(child, 'created_at', cr, p4)
      if (p3 .and. p4) then; ttl_ok = ((ex - cr) <= maxttl)
      else if (p3) then;     ttl_ok = .true.
      else;                  ttl_ok = .false.; end if
    end if
    check_delegation_caveats = (depth_ok .and. ttl_ok)
  end function check_delegation_caveats

  ! ── §3.6 M3 multi-signature root ──
  logical function is_multisig(cap)
    type(entity_t), intent(in) :: cap
    type(ecf_value_t) :: g
    g = ent_field(cap, 'granter')
    is_multisig = (g%vkind == EV_MAP)
  end function is_multisig

  ! parse the granter union -> threshold + signers list; th<0 signals single-sig.
  subroutine multi_granter_of(cap, threshold, signers)
    type(entity_t),           intent(in)  :: cap
    integer(int64),           intent(out) :: threshold
    type(str_t), allocatable, intent(out) :: signers(:)   ! hex of each signer hash
    type(ecf_value_t) :: g, arr, it
    integer :: i
    logical :: present
    threshold = -1
    allocate(signers(0))
    g = ent_field(cap, 'granter')
    if (g%vkind /= EV_MAP) return
    arr = m_array(g, 'signers')
    do i = 1, arr_count(arr)
      it = arr_item(arr, i)
      if (it%vkind == EV_BYTES) call sl_push(signers, hexlc(val_bytes(it)))
    end do
    call m_uint(g, 'threshold', threshold, present)
    if (.not. present) threshold = 0
  end subroutine multi_granter_of

  subroutine sl_push(l, s)
    type(str_t), allocatable, intent(inout) :: l(:)
    character(len=*),         intent(in)    :: s
    type(str_t), allocatable :: tmp(:)
    allocate(tmp(size(l) + 1))
    if (size(l) > 0) tmp(1:size(l)) = l
    tmp(size(tmp))%s = s
    call move_alloc(tmp, l)
  end subroutine sl_push

  logical function has_dup(l)
    type(str_t), intent(in) :: l(:)
    integer :: i, j
    has_dup = .false.
    do i = 1, size(l)
      do j = i+1, size(l)
        if (l(i)%s == l(j)%s) then; has_dup = .true.; return; end if
      end do
    end do
  end function has_dup

  logical function sl_has(l, s)
    type(str_t), intent(in) :: l(:)
    character(len=*), intent(in) :: s
    integer :: i
    sl_has = .false.
    do i = 1, size(l)
      if (l(i)%s == s) then; sl_has = .true.; return; end if
    end do
  end function sl_has

  function peer_id_of_signer(inc, store, signer_hex) result(pid)
    type(entity_t), intent(in) :: inc(:)
    type(store_t),  intent(in) :: store
    character(len=*), intent(in) :: signer_hex
    character(len=:), allocatable :: pid
    type(entity_t) :: p
    integer(int8), allocatable :: pk(:)
    integer :: i
    pid = ''
    p%present = .false.
    do i = 1, size(inc)
      if (hexlc(ent_hash(inc(i))) == signer_hex) then; p = inc(i); exit; end if
    end do
    if (.not. p%present) return
    pk = ent_bytes(p, 'public_key')
    if (size(pk) == 0) return
    pid = peer_id_of_pubkey(pk)
  end function peer_id_of_signer

  logical function verify_multisig_root(local, inc, store, cap, signers, threshold)
    character(len=*), intent(in) :: local
    type(entity_t),   intent(in) :: inc(:)
    type(store_t),    intent(in) :: store
    type(entity_t),   intent(in) :: cap
    type(str_t),      intent(in) :: signers(:)
    integer(int64),   intent(in) :: threshold
    type(str_t), allocatable :: valid(:)
    type(entity_t) :: sgn, signer_peer
    integer(int8), allocatable :: caph(:), grantee(:)
    integer :: i, n, count
    integer(int64) :: now, nb, ex
    logical :: pnb, pex, local_in
    verify_multisig_root = .false.
    n = size(signers)
    if (size(ent_bytes(cap, 'parent')) /= 0) return
    if (n < 2) return
    if (threshold < 2 .or. threshold > n) return
    if (has_dup(signers)) return
    local_in = .false.
    do i = 1, n
      if (peer_id_of_signer(inc, store, signers(i)%s) == local) then; local_in = .true.; exit; end if
    end do
    if (.not. local_in) return
    now = cap_now_ms()
    call ent_uint(cap, 'not_before', nb, pnb); if (pnb .and. now < nb) return
    call ent_uint(cap, 'expires_at', ex, pex); if (pex .and. ex < now) return
    grantee = ent_bytes(cap, 'grantee')
    if (size(grantee) == 0) return
    block
      type(entity_t) :: ge
      ge = cap_resolve(inc, store, grantee)
      if (.not. ge%present) return
    end block
    ! §5.5 M4 k-of-n: >= threshold distinct quorum members validly signed the cap hash.
    caph = ent_hash(cap)
    allocate(valid(0))
    do i = 1, n
      if (sl_has(valid, signers(i)%s)) cycle
      signer_peer%present = .false.
      block
        integer :: j
        do j = 1, size(inc)
          if (hexlc(ent_hash(inc(j))) == signers(i)%s) then; signer_peer = inc(j); exit; end if
        end do
      end block
      if (.not. signer_peer%present) cycle
      ! find a signature over caph by this signer
      block
        integer :: j
        integer(int8), allocatable :: sh(:)
        do j = 1, size(inc)
          if (ent_type(inc(j)) /= 'system/signature') cycle
          if (.not. hash_eq(ent_bytes(inc(j), 'target'), caph)) cycle
          sh = ent_bytes(inc(j), 'signer')
          if (hexlc(sh) == signers(i)%s .and. id_verify_signature(inc(j), signer_peer)) then
            call sl_push(valid, signers(i)%s); exit
          end if
        end do
      end block
    end do
    count = size(valid)
    verify_multisig_root = (int(count, int64) >= threshold)
  end function verify_multisig_root

  ! ── §5.5 chain verification -> CV_ALLOW / CV_AUTHZ_DENY; sets unresolvable for the
  ! §5.5 grantee carve-out (-> 401). ──
  integer function cap_verify_chain(local, store, cap, inc, unresolvable)
    character(len=*), intent(in)  :: local
    type(store_t),    intent(in)  :: store
    type(entity_t),   intent(in)  :: cap
    type(entity_t),   intent(in)  :: inc(:)
    logical,          intent(out) :: unresolvable
    type(entity_t), allocatable :: chain(:)
    type(entity_t) :: root, current, sgn, granter, parent
    type(str_t), allocatable :: signers(:)
    integer(int8), allocatable :: rgh(:), pk(:), gh(:), geh(:), signer(:), pg(:), cg(:)
    integer :: nn, i
    integer(int64) :: root_th, now, nb, ex
    logical :: ok, root_ok, good, pnb, pex, link_ok
    character(len=:), allocatable :: child_peer, parent_peer
    cap_verify_chain = CV_AUTHZ_DENY
    unresolvable = .false.
    call collect_chain(cap, inc, store, chain, ok)
    if (.not. ok) return
    nn = size(chain)
    root = chain(nn)
    call multi_granter_of(root, root_th, signers)
    if (root_th >= 0) then
      root_ok = verify_multisig_root(local, inc, store, root, signers, root_th)
    else
      rgh = ent_bytes(root, 'granter')
      granter%present = .false.
      if (size(rgh) > 0) granter = cap_resolve(inc, store, rgh)
      pk = null_bytes()
      if (granter%present) pk = ent_bytes(granter, 'public_key')
      root_ok = (size(pk) > 0)
      if (root_ok) root_ok = (peer_id_of_pubkey(pk) == local)
    end if
    if (.not. root_ok) return
    good = .true.
    do i = 1, nn
      if (.not. good) exit
      current = chain(i)
      if (is_multisig(current)) then
        if (i /= nn) good = .false.
        cycle
      end if
      gh = ent_bytes(current, 'granter')
      if (size(gh) > 0) then
        sgn = cap_find_signature(ent_hash(current), inc)
        granter = cap_resolve(inc, store, gh)
        if (sgn%present .and. granter%present) then
          signer = ent_bytes(sgn, 'signer')
          if (.not. (size(signer) > 0 .and. hash_eq(signer, gh) .and. id_verify_signature(sgn, granter))) good = .false.
        else
          good = .false.
        end if
      else
        good = .false.
      end if
      geh = ent_bytes(current, 'grantee')
      if (size(geh) > 0) then
        block
          type(entity_t) :: ge
          ge = cap_resolve(inc, store, geh)
          if (.not. ge%present) then; unresolvable = .true.; return; end if
        end block
      else
        unresolvable = .true.; return
      end if
      ! CAP-6a FIRST (§6.2): a present-but-unrepresentable expires_at / not_before /
      ! created_at is MALFORMED and must be refused outright. This has to run BEFORE the
      ! two range checks below, because those use ent_uint, which cannot tell "absent"
      ! from "present but not EV_UINT" -- so on its own it would skip the check and honor
      ! the token (fail-open).
      if (.not. cap_temporal_fields_representable(current)) good = .false.
      now = cap_now_ms()
      call ent_uint(current, 'not_before', nb, pnb); if (pnb .and. now < nb) good = .false.
      call ent_uint(current, 'expires_at', ex, pex); if (pex .and. ex < now) good = .false.
      if (i < nn) then
        parent = chain(i+1)
        child_peer  = link_granter_peer(inc, store, local, current)
        parent_peer = link_granter_peer(inc, store, local, parent)
        if (len(child_peer) == 0 .or. len(parent_peer) == 0) then
          good = .false.
        else
          pg = ent_bytes(parent, 'grantee')
          cg = ent_bytes(current, 'granter')
          link_ok = (size(pg) > 0 .and. size(cg) > 0 .and. hash_eq(pg, cg))
          if (link_ok) link_ok = is_attenuated(local, child_peer, parent_peer, current, parent)
          if (link_ok) link_ok = check_delegation_caveats(parent, current, i)
          if (.not. link_ok) good = .false.
        end if
      end if
    end do
    if (good) cap_verify_chain = CV_ALLOW
  end function cap_verify_chain

  function null_bytes() result(b)
    integer(int8), allocatable :: b(:)
    allocate(b(0))
  end function null_bytes

  logical function cap_is_revoked(local, store, cap, inc)
    character(len=*), intent(in) :: local
    type(store_t),    intent(in) :: store
    type(entity_t),   intent(in) :: cap
    type(entity_t),   intent(in) :: inc(:)
    type(entity_t), allocatable :: chain(:)
    integer(int8), allocatable :: root_hash(:)
    logical :: ok
    cap_is_revoked = .false.
    call collect_chain(cap, inc, store, chain, ok)
    if (ok) then; root_hash = ent_hash(chain(size(chain))); else; root_hash = ent_hash(cap); end if
    if (revoke_marker(local, store, ent_hash(cap))) then; cap_is_revoked = .true.; return; end if
    cap_is_revoked = revoke_marker(local, store, root_hash)
  end function cap_is_revoked

  logical function revoke_marker(local, store, h)
    character(len=*), intent(in) :: local
    type(store_t),    intent(in) :: store
    integer(int8),    intent(in) :: h(:)
    type(entity_t) :: e
    e = store_get_at(store, '/' // trim(local) // '/system/capability/revocations/' // hexlc(h))
    revoke_marker = e%present
  end function revoke_marker

  ! ── §5.2 verify-request (3-way + unresolvable) ──
  integer function cap_verify_request(local, store, env, unresolvable)
    character(len=*), intent(in)  :: local
    type(store_t),    intent(in)  :: store
    type(envelope_t), intent(in)  :: env
    logical,          intent(out) :: unresolvable
    type(entity_t) :: exec, sgn, author, cap
    integer(int8), allocatable :: author_h(:), signer(:), ch(:), grantee(:)
    integer :: verdict
    unresolvable = .false.
    exec = env%root
    sgn = cap_find_signature(ent_hash(exec), env%inc)
    if (.not. sgn%present) then; cap_verify_request = CV_AUTHN_FAIL; return; end if
    author_h = ent_bytes(exec, 'author')
    signer = ent_bytes(sgn, 'signer')
    if (.not. (size(signer) > 0 .and. size(author_h) > 0 .and. hash_eq(signer, author_h))) then
      cap_verify_request = CV_AUTHN_FAIL; return
    end if
    author = env_included_get(env, author_h)
    if (.not. author%present) then; cap_verify_request = CV_AUTHN_FAIL; return; end if
    if (.not. id_verify_signature(sgn, author)) then; cap_verify_request = CV_AUTHN_FAIL; return; end if
    ch = ent_bytes(exec, 'capability')
    cap%present = .false.
    if (size(ch) > 0) cap = env_included_get(env, ch)
    if (.not. cap%present) then; cap_verify_request = CV_AUTHZ_DENY; return; end if
    if (cap_chain_exceeds_depth(store, cap, env%inc)) then; cap_verify_request = CV_CHAIN_TOO_DEEP; return; end if
    verdict = cap_verify_chain(local, store, cap, env%inc, unresolvable)
    if (unresolvable) then; cap_verify_request = CV_AUTHZ_DENY; return; end if
    if (verdict /= CV_ALLOW) then; cap_verify_request = CV_AUTHZ_DENY; return; end if
    grantee = ent_bytes(cap, 'grantee')
    if (.not. (size(grantee) > 0 .and. hash_eq(grantee, author_h))) then; cap_verify_request = CV_AUTHZ_DENY; return; end if
    if (cap_is_revoked(local, store, cap, env%inc)) then; cap_verify_request = CV_AUTHZ_DENY; return; end if
    cap_verify_request = CV_ALLOW
  end function cap_verify_request


  ! §6.2 CAP-6a: .true. iff every temporal field on a RECEIVED token is either absent
  ! (legal) or representable as a uint64.
  !
  ! This is the reader-side half of CAP-6 and it is where a peer fails OPEN. ent_uint
  ! reports present=.false. BOTH when a field is ABSENT and when it is PRESENT but not
  ! EV_UINT -- a negative integer or a bignum -- so a token carrying expires_at:-1
  ! silently skipped the expiry check and was honored with 200. §6.2 CAP-6a is explicit:
  ! such a token "is malformed. A verifier MUST refuse it and MUST NOT treat the
  ! unrepresentable field as absent." An absent expires_at stays legal and is NOT
  ! rejected here.
  !
  ! Refusal must be the §5.2 capability_denied disposition (a status-bearing response),
  ! never a decode-layer silent drop or a transport close.
  logical function cap_temporal_fields_representable(tok) result(ok)
    type(entity_t), intent(in) :: tok
    type(ecf_value_t) :: v
    integer :: k
    character(len=10), parameter :: keys(3) = &
      [character(len=10) :: 'expires_at', 'not_before', 'created_at']
    ok = .true.
    do k = 1, 3
      v = ent_field(tok, trim(keys(k)))
      if (v%vkind == EV_ABSENT) cycle          ! absent is legal
      if (v%vkind /= EV_UINT) then; ok = .false.; return; end if
    end do
  end function cap_temporal_fields_representable

  ! §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
  ! created_at. Rule 3: a conversion that is not representable is treated as ABSENT
  ! (ok=.false.) exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
  ! representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
  ! bound no reader can distinguish from a deliberate one.
  !
  ! FORTRAN-SPECIFIC: integer(int64) is SIGNED, and this peer's whole discovery axis is
  ! the fixed-width signed-only number model. A wrap here shows up as a NEGATIVE sum, not
  ! as a small positive one, so the guard tests the sign as well as the ordering.
  !
  ! ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
  ! yielding created_at (expire immediately). The absent field is the only "no bound"
  ! spelling, and falling out of the arithmetic is what keeps the two from collapsing.
  subroutine cap_add_ttl(created_at, ttl, val, ok)
    integer(int64), intent(in)  :: created_at, ttl
    integer(int64), intent(out) :: val
    logical,        intent(out) :: ok
    val = 0_int64; ok = .false.
    if (ttl < 0_int64) return
    val = created_at + ttl
    if (val < created_at) then; val = 0_int64; return; end if
    ok = .true.
  end subroutine cap_add_ttl

end module entity_core_capability
