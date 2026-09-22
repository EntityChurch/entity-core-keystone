! entity-core-protocol-fortran — src/peer.f90 (peer assembly: L2 interaction + bootstrap
! + the MUST system handlers + the §6.5 dispatch chain + the §6.9/§6.9a seed policy).
!
! The pure protocol brain: dispatch is a function from an inbound envelope to an outbound
! response envelope; the transport plumbing lives in transport.f90 (peer `use`s it one-way,
! so there is no module cycle). A peer is a SINGLETON in this module's SAVEd state — the
! profile [async] "one image, one thread" model: one OS process is one peer, driven by a
! single-threaded select-pump (peer_serve). §4.8 store-safety is STRUCTURAL: one frame is
! dispatched to completion before the next event is polled, so g_store is never raced.
!
! Only EXECUTE / EXECUTE_RESPONSE are wire message types (§3.3); hello/authenticate are
! OPERATIONS on system/protocol/connect (§4.1). request_id demux (§6.11) is in transport;
! the §6.13(b) handler-outbound reentry is a MANUAL pump on the same loop (the correlation-
! map tax the non-actor/non-CSP peers pay). The §4.10 floor is built in: 413 before
! buffering (net-shim + send_413), the 400 chain_depth_exceeded structural pre-check.
module entity_core_peer
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor, only : ecf_value_t, EV_MAP, EV_ABSENT
  use entity_core_val
  use entity_core_ent
  use entity_core_wire
  use entity_core_store
  use entity_core_identity
  use entity_core_capability
  use entity_core_coretypes
  use entity_core_transport
  implicit none
  private

  ! handler routine ids
  integer, parameter :: R_CONNECT = 1, R_TREE = 2, R_HANDLERS = 3, R_TYPE = 4, &
                        R_CAPABILITY = 5, R_ECHO = 6, R_DISPATCH_OUTBOUND = 7

  integer, parameter :: MAXCONN = 512

  type :: outcome_t
    integer                     :: status = 200
    type(entity_t)              :: result
    type(entity_t), allocatable :: inc(:)
  end type outcome_t

  ! a minted capability: the token entity + its detached self-signature (§6.9a.0 shape 1).
  type :: minted_t
    type(entity_t) :: token, sig
  end type minted_t

  type, public :: session_t
    logical                       :: ok = .false.
    integer                       :: io = -1
    integer                       :: req_ctr = 0
    character(len=:), allocatable :: remote_peer_id
    type(id_t)                    :: ident
    type(entity_t)                :: cap, granter, cap_sig
  end type session_t

  ! ── singleton peer state ──
  type(id_t),      save :: g_ident
  type(store_t),   save :: g_store
  character(len=:), allocatable, save :: g_local
  logical, save :: g_open_grants = .false.
  logical, save :: g_conformance = .false.
  integer, save :: g_out_ctr = 0

  ! handler table (stripped pattern -> routine id)
  type(str_t), allocatable, save :: h_pattern(:)
  integer,     allocatable, save :: h_routine(:)

  ! per-connection state
  integer,          save :: c_io(MAXCONN) = 0            ! 0 = free
  logical,          save :: c_estab(MAXCONN) = .false.
  logical,          save :: c_has_nonce(MAXCONN) = .false.
  integer(int8),    save :: c_nonce(32, MAXCONN) = 0_int8
  character(len=128), save :: c_hello_pid(MAXCONN) = ''
  integer,          save :: c_n = 0

  public :: peer_create, peer_local, peer_listen, peer_serve, peer_shutdown
  public :: peer_dial, sess_execute, sess_execute_async, sess_await, sess_response
  public :: peer_random_bytes

contains

  ! ═══════════════ construction + bootstrap ═══════════════
  subroutine peer_create(seed, open_grants, conformance)
    integer(int8), intent(in) :: seed(32)
    logical,       intent(in) :: open_grants, conformance
    g_ident = id_of_seed(seed)
    g_store = store_new()
    g_local = g_ident%peer_id
    g_open_grants = open_grants
    g_conformance = conformance
    allocate(h_pattern(0), h_routine(0))
    call bootstrap()
  end subroutine peer_create

  function peer_local() result(s)
    character(len=:), allocatable :: s
    s = g_local
  end function peer_local

  function peer_abs(rel) result(p)
    character(len=*), intent(in) :: rel
    character(len=:), allocatable :: p
    p = '/' // g_local // '/' // rel
  end function peer_abs

  function peer_random_bytes(n) result(b)
    use entity_core_net, only : random_bytes
    integer, intent(in) :: n
    integer(int8) :: b(n)
    b = random_bytes(n)
  end function peer_random_bytes

  ! op-spec map {input_type?, output_type?}
  function op_spec(input, output) result(m)
    character(len=*), intent(in) :: input, output
    type(ecf_value_t) :: m
    m = v_map_empty()
    if (len_trim(input)  > 0) m = v_map_put(m, 'input_type',  v_text(input))
    if (len_trim(output) > 0) m = v_map_put(m, 'output_type', v_text(output))
  end function op_spec

  subroutine reg_handler(pattern, routine, name, operations)
    character(len=*),  intent(in) :: pattern, name
    integer,           intent(in) :: routine
    type(ecf_value_t), intent(in) :: operations
    type(str_t), allocatable :: np(:)
    integer, allocatable :: nr(:)
    type(ecf_value_t) :: hp, im
    type(minted_t) :: m
    ! table
    allocate(np(size(h_pattern) + 1), nr(size(h_routine) + 1))
    if (size(h_pattern) > 0) then; np(1:size(h_pattern)) = h_pattern; nr(1:size(h_routine)) = h_routine; end if
    np(size(np))%s = pattern
    nr(size(nr))   = routine
    call move_alloc(np, h_pattern); call move_alloc(nr, h_routine)
    ! handler entity + interface entity
    hp = v_map_put(v_map_empty(), 'interface', v_text('system/handler/' // pattern))
    call store_bind(g_store, peer_abs(pattern), ent_make('system/handler', hp))
    im = v_map_put(v_map_empty(), 'pattern', v_text(pattern))
    im = v_map_put(im, 'name', v_text(name))
    im = v_map_put(im, 'operations', operations)
    call store_bind(g_store, peer_abs('system/handler/' // pattern), ent_make('system/handler/interface', im))
    ! grants marker
    m = mint_token(g_ident%id_hash, v_arr_empty(), null_hash())
    call store_bind(g_store, peer_abs('system/capability/grants/' // pattern), m%token)
  end subroutine reg_handler

  subroutine bootstrap()
    type(ecf_value_t) :: ops, floor, owner_g, dg, pe
    type(minted_t) :: owner
    character(len=:), allocatable :: policy_base
    call store_put_entity(g_store, g_ident%peer_entity)
    call ct_publish(g_store, g_local)

    ops = v_map_put(v_map_put(v_map_empty(), 'get', op_spec('','')), 'put', op_spec('',''))
    call reg_handler('system/tree', R_TREE, 'Tree', ops)
    ops = v_map_put(v_map_empty(), 'register', op_spec('system/handler/register-request', 'system/handler/register-result'))
    ops = v_map_put(ops, 'unregister', op_spec('system/handler/unregister-request', ''))
    call reg_handler('system/handler', R_HANDLERS, 'Handlers', ops)
    ops = v_map_put(v_map_empty(), 'validate', op_spec('system/type/validate-request', 'system/type/validate-result'))
    call reg_handler('system/type', R_TYPE, 'Types', ops)
    ops = v_map_put(v_map_empty(), 'request', op_spec('system/capability/request', 'system/capability/grant'))
    ops = v_map_put(ops, 'revoke', op_spec('system/capability/revoke-request', ''))
    ops = v_map_put(ops, 'configure', op_spec('system/capability/policy-entry', ''))
    ops = v_map_put(ops, 'delegate', op_spec('system/capability/delegate-request', 'system/capability/grant'))
    call reg_handler('system/capability', R_CAPABILITY, 'Capability', ops)
    ops = v_map_put(v_map_put(v_map_empty(), 'hello', op_spec('','')), 'authenticate', op_spec('',''))
    call reg_handler('system/protocol/connect', R_CONNECT, 'Connect', ops)

    ! §6.9a Peer Authority Bootstrap: self-owner cap + default scope-template entry.
    policy_base = '/' // g_local // '/system/capability/policy/'
    owner = mint_token(g_ident%id_hash, owner_grants(), null_hash())
    call store_bind(g_store, policy_base // hexlc(g_ident%id_hash), owner%token)
    call store_bind(g_store, '/' // g_local // '/system/signature/' // hexlc(ent_hash(owner%token)), owner%sig)
    if (g_open_grants) then; dg = open_grants_scope(); else; dg = discovery_floor(); end if
    pe = v_map_put(v_map_put(v_map_empty(), 'peer_pattern', v_text('default')), 'grants', dg)
    call store_bind(g_store, policy_base // 'default', ent_make('system/capability/policy-entry', pe))

    ! §7a conformance handlers — only under --validate.
    if (g_conformance) then
      ops = v_map_put(v_map_empty(), 'echo', op_spec('',''))
      call reg_handler('system/validate/echo', R_ECHO, 'validate-echo', ops)
      ops = v_map_put(v_map_empty(), 'dispatch', op_spec('',''))
      call reg_handler('system/validate/dispatch-outbound', R_DISPATCH_OUTBOUND, 'validate-dispatch-outbound', ops)
    end if
  end subroutine bootstrap

  ! ═══════════════ grant construction (§4.4 / §5.4) ═══════════════
  function discovery_floor() result(a)
    type(ecf_value_t) :: a
    a = v_arr_empty()
    a = v_arr_add(a, cap_grant('system/tree', 'system/type/* system/handler/*', 'get', ''))
    a = v_arr_add(a, cap_grant('system/capability', '', 'request', ''))
  end function discovery_floor

  function open_grants_scope() result(a)
    type(ecf_value_t) :: a
    a = v_arr_add(v_arr_empty(), cap_grant('*', '* /*/*', '*', '*'))
  end function open_grants_scope

  function owner_grants() result(a)
    type(ecf_value_t) :: a
    a = v_arr_add(v_arr_empty(), cap_grant('*', '*', '*', g_local))
  end function owner_grants

  ! ═══════════════ token mint (§4.4 / §6.9a) ═══════════════
  function null_hash() result(b)
    integer(int8), allocatable :: b(:)
    allocate(b(0))
  end function null_hash

  ! mint_token_at at the current instant with no §5.6 ceiling. Used by the paths that
  ! mint a self-issued grant from local authority (bootstrap, handler registration, the
  ! §4.4 handshake), where no MIN_DEFINED term is in play.
  function mint_token(grantee_hash, grants, parent) result(m)
    integer(int8),     intent(in) :: grantee_hash(:)
    type(ecf_value_t), intent(in) :: grants
    integer(int8),     intent(in) :: parent(:)
    type(minted_t) :: m
    m = mint_token_at(cap_now_ms(), grantee_hash, grants, parent, 0_int64, .false.)
  end function mint_token

  ! Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
  !
  ! has_expires=.false. means no term was defined and the token genuinely has no expiry
  ! (the ONLY "no bound" spelling). A supplied expires_at is emitted verbatim -- including
  ! a value equal to created_at, which §5.6 rule 2 requires for ttl_ms == 0 and which
  ! means "already expired at every observable instant", not "unbounded".
  !
  ! created_at is supplied rather than sampled here so a computed expiry is guaranteed to
  ! be relative to the SAME instant that lands in the token; sampling the clock twice
  ! skews the two.
  function mint_token_at(created_at, grantee_hash, grants, parent, expires_at, has_expires) result(m)
    integer(int64),    intent(in) :: created_at
    integer(int8),     intent(in) :: grantee_hash(:)
    type(ecf_value_t), intent(in) :: grants
    integer(int8),     intent(in) :: parent(:)
    integer(int64),    intent(in) :: expires_at
    logical,           intent(in) :: has_expires
    type(minted_t) :: m
    type(ecf_value_t) :: tm
    tm = v_map_empty()
    tm = v_map_put(tm, 'granter', v_bytes(g_ident%id_hash))
    tm = v_map_put(tm, 'grantee', v_bytes(grantee_hash))
    tm = v_map_put(tm, 'grants', grants)
    tm = v_map_put(tm, 'created_at', v_uint(created_at))
    if (has_expires) tm = v_map_put(tm, 'expires_at', v_uint(expires_at))
    if (size(parent) > 0) tm = v_map_put(tm, 'parent', v_bytes(parent))
    m%token = ent_make('system/capability/token', tm)
    m%sig   = id_sign(g_ident, m%token)
  end function mint_token_at

  function cap_included(m) result(inc)
    type(minted_t), intent(in) :: m
    type(entity_t), allocatable :: inc(:)
    allocate(inc(3))
    inc(1) = m%token
    inc(2) = g_ident%peer_entity
    inc(3) = m%sig
  end function cap_included

  ! ═══════════════ §6.9a seed policy ═══════════════
  function seed_entry_grants(e) result(g)
    type(entity_t), intent(in) :: e
    type(ecf_value_t) :: g
    type(entity_t) :: sgn
    character(len=:), allocatable :: sig_path
    g = v_arr_empty()
    if (ent_type(e) == 'system/capability/token') then
      sig_path = '/' // g_local // '/system/signature/' // hexlc(ent_hash(e))
      sgn = store_get_at(g_store, sig_path)
      if (sgn%present) then
        if (id_verify_signature(sgn, g_ident%peer_entity)) g = m_array(ent_data_map(e), 'grants')
      end if
      return
    end if
    if (ent_type(e) == 'system/capability/policy-entry') g = m_array(ent_data_map(e), 'grants')
  end function seed_entry_grants

  function derive_seed_grants(remote_peer, remote_peer_id) result(g)
    type(entity_t),   intent(in) :: remote_peer
    character(len=*), intent(in) :: remote_peer_id
    type(ecf_value_t) :: g, floor, policy
    type(entity_t) :: entry
    character(len=:), allocatable :: base
    integer :: i
    base = '/' // g_local // '/system/capability/policy/'
    entry = store_get_at(g_store, base // hexlc(ent_hash(remote_peer)))
    if (.not. entry%present) entry = store_get_at(g_store, base // remote_peer_id)
    if (.not. entry%present) entry = store_get_at(g_store, base // 'default')
    floor = discovery_floor()
    if (.not. entry%present) then; g = floor; return; end if
    policy = seed_entry_grants(entry)
    if (arr_count(policy) == 0) then; g = floor; return; end if
    g = floor
    do i = 1, arr_count(policy)
      g = v_arr_add(g, arr_item(policy, i))
    end do
  end function derive_seed_grants

  ! ═══════════════ handler resolution (§6.6) ═══════════════
  function resolve_handler(path) result(pattern)
    character(len=*), intent(in) :: path
    character(len=:), allocatable :: pattern, prefix, rest, seg
    type(str_t), allocatable :: segs(:)
    type(entity_t) :: e
    integer :: i, j, slash
    pattern = ''
    allocate(segs(0))
    rest = path
    do while (len(rest) > 0)
      slash = index(rest, '/')
      if (slash == 0) then; call push_seg(segs, rest); rest = ''
      else; call push_seg(segs, rest(1:slash-1)); rest = rest(slash+1:); end if
    end do
    do i = size(segs), 1, -1
      prefix = ''
      do j = 1, i
        if (j == 1) then; prefix = segs(j)%s; else; prefix = prefix // '/' // segs(j)%s; end if
      end do
      e = store_get_at(g_store, prefix)
      if (e%present) then
        if (ent_type(e) == 'system/handler') then; pattern = prefix; return; end if
      end if
    end do
  end function resolve_handler

  subroutine push_seg(l, s)
    type(str_t), allocatable, intent(inout) :: l(:)
    character(len=*),         intent(in)    :: s
    type(str_t), allocatable :: tmp(:)
    allocate(tmp(size(l) + 1))
    if (size(l) > 0) tmp(1:size(l)) = l
    tmp(size(tmp))%s = s
    call move_alloc(tmp, l)
  end subroutine push_seg

  function strip_local(pattern) result(s)
    character(len=*), intent(in) :: pattern
    character(len=:), allocatable :: s, pfx
    pfx = '/' // g_local // '/'
    if (len(pattern) >= len(pfx)) then
      if (pattern(1:len(pfx)) == pfx) then; s = pattern(len(pfx)+1:); return; end if
    end if
    s = pattern
  end function strip_local

  integer function handler_routine(stripped)
    character(len=*), intent(in) :: stripped
    integer :: i
    handler_routine = 0
    do i = 1, size(h_pattern)
      if (h_pattern(i)%s == stripped) then; handler_routine = h_routine(i); return; end if
    end do
  end function handler_routine

  ! ═══════════════ dispatch chain (§6.5) ═══════════════
  ! returns .false. in has_resp for a non-EXECUTE root (§3.3).
  subroutine peer_dispatch(slot, env, resp_env, has_resp)
    integer,          intent(in)  :: slot
    type(envelope_t), intent(in)  :: env
    type(envelope_t), intent(out) :: resp_env
    logical,          intent(out) :: has_resp
    type(outcome_t) :: oc
    type(entity_t)  :: resp
    character(len=:), allocatable :: rid
    has_resp = .false.
    if (ent_type(env%root) /= 'system/protocol/execute') return
    rid = ent_text(env%root, 'request_id')
    oc = dispatch_inner(slot, env)
    resp = wire_make_response(rid, oc%status, oc%result)
    if (.not. allocated(oc%inc)) allocate(oc%inc(0))
    resp_env = env_make(resp, oc%inc)
    has_resp = .true.
  end subroutine peer_dispatch

  function dispatch_inner(slot, env) result(oc)
    integer,          intent(in) :: slot
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, caller_cap
    character(len=:), allocatable :: uri, operation, path, pattern, stripped, granter_peer
    integer(int8), allocatable :: cap_h(:)
    integer :: verdict, routine
    logical :: unresolvable, invalid
    exec = env%root
    uri = ent_text(exec, 'uri')
    operation = ent_text(exec, 'operation')
    if (uri == 'system/protocol/connect') then
      oc = call_handler(R_CONNECT, slot, operation, env, ent_absent(), '', '')
      return
    end if
    ! §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
    ! sit below the §5.2 verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace
    ! took the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the
    ! caller to authenticate and retry, and for a foreign-namespace address that retry
    ! cannot succeed at any authentication state — so the 401 names a remedy that does not
    ! exist." §6.5 step 3 calls it "a gate, not an ordering preference".
    call cap_canonicalize(g_local, cap_normalize_uri(uri), path, invalid)
    if (.not. invalid) then
      if (cap_extract_peer(g_local, path) /= g_local) then; oc = out_err(400, 'invalid_request', 'not local peer'); return; end if
    end if
    verdict = cap_verify_request(g_local, g_store, env, unresolvable)
    if (unresolvable) then; oc = out_err(401, 'unresolvable_grantee', ''); return; end if
    select case (verdict)
    case (CV_AUTHN_FAIL);     oc = out_err(401, 'authentication_failed', ''); return
    case (CV_AUTHZ_DENY);     oc = out_err(403, 'capability_denied', ''); return
    case (CV_CHAIN_TOO_DEEP); oc = out_err(400, 'chain_depth_exceeded', ''); return
    end select
    call cap_canonicalize(g_local, cap_normalize_uri(uri), path, invalid)
    if (invalid) then; oc = out_err(400, 'invalid_path', ''); return; end if
    ! (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
    ! 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
    pattern = resolve_handler(path)
    if (len(pattern) == 0) then; oc = out_err(404, 'handler_not_found', path); return; end if
    cap_h = ent_bytes(exec, 'capability')
    caller_cap%present = .false.
    if (size(cap_h) > 0) caller_cap = env_included_get(env, cap_h)
    if (.not. caller_cap%present) then; oc = out_err(403, 'capability_denied', ''); return; end if
    granter_peer = cap_resolve_granter_peer_id(env%inc, g_store, caller_cap)
    if (len(granter_peer) == 0) granter_peer = g_local
    if (.not. cap_check_permission(g_local, granter_peer, exec, caller_cap, pattern)) then
      oc = out_err(403, 'capability_denied', ''); return
    end if
    stripped = strip_local(pattern)
    routine = handler_routine(stripped)
    if (routine == 0) then; oc = out_err(404, 'handler_not_found', pattern); return; end if
    oc = call_handler(routine, slot, operation, env, caller_cap, granter_peer, pattern)
  end function dispatch_inner

  function call_handler(routine, slot, operation, env, caller_cap, granter_peer, pattern) result(oc)
    integer,          intent(in) :: routine, slot
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(entity_t),   intent(in) :: caller_cap
    character(len=*), intent(in) :: granter_peer, pattern
    type(outcome_t) :: oc
    select case (routine)
    case (R_CONNECT);    oc = hnd_connect(slot, operation, env)
    case (R_TREE);       oc = hnd_tree(operation, env)
    case (R_HANDLERS);   oc = hnd_handlers(operation, env)
    case (R_TYPE);       oc = hnd_type(operation, env)
    case (R_CAPABILITY); oc = hnd_capability(operation, env, caller_cap)
    case (R_ECHO);       oc = hnd_echo(operation, env)
    case (R_DISPATCH_OUTBOUND); oc = hnd_dispatch_outbound(slot, operation, env, caller_cap, granter_peer)
    case default;        oc = out_err(501, 'unsupported_operation', '')
    end select
  end function call_handler

  ! ── outcome helpers ──
  function out_ok(result, inc) result(oc)
    type(entity_t), intent(in) :: result
    type(entity_t), intent(in) :: inc(:)
    type(outcome_t) :: oc
    oc%status = 200
    oc%result = result
    oc%inc = inc
  end function out_ok

  function out_ok0(result) result(oc)
    type(entity_t), intent(in) :: result
    type(outcome_t) :: oc
    oc%status = 200
    oc%result = result
    allocate(oc%inc(0))
  end function out_ok0

  function out_err(status, code, message) result(oc)
    integer,          intent(in) :: status
    character(len=*), intent(in) :: code, message
    type(outcome_t) :: oc
    oc%status = status
    oc%result = wire_error_result(code, message)
    allocate(oc%inc(0))
  end function out_err

  ! ═══════════════ MUST handlers ═══════════════
  ! ── §4.1/§4.6 connect ──
  function hnd_connect(slot, operation, env) result(oc)
    integer,          intent(in) :: slot
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    if (operation == 'hello') then; oc = connect_hello(slot, env)
    else if (operation == 'authenticate') then; oc = connect_authenticate(slot, env)
    ! §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
    ! 400 invalid_request, not the 501 every other handler answers. The table separates
    ! a STATE conflict from an UNKNOWN operation because they select different remedies
    ! — "an unknown connect operation is not out of order at all; it exists in no
    ! state", so connection_sequence_error would point the caller at its ORDERING when
    ! the defect is its OPERATION NAME. Row 10 is scoped "in any state", so this arm
    ! covers pre-handshake AND established; the genuine sequence cases are refused
    ! inside connect_hello/connect_authenticate, with 409.
    !
    ! SCOPED TO THIS FUNCTION DELIBERATELY. The generic registered-handler rule (§3.3's
    ! 501 row, §6.2) is a different contract and is separately gated; moving the other
    ! handlers' 501 would trade one green check for another.
    else; oc = out_err(400, 'invalid_request', 'connect: unknown operation ' // operation); end if
  end function hnd_connect

  ! §4.5: does `key` carry at least one text entry? Separates the MALFORMED case
  ! (absent, empty, or not an array of text) from the we-compared-and-disagreed case,
  ! which take different §4.7 codes. negotiation_disjoint deliberately conflates the two
  ! — absent means "no constraint" there — so `protocols`, which is Required with no
  ! default, needs this second question asked first.
  logical function protocols_present(params)
    type(entity_t), intent(in) :: params
    type(ecf_value_t) :: d, arr
    integer :: i
    protocols_present = .false.
    if (.not. params%present) return
    d = ent_data_map(params)
    if (.not. m_has(d, 'protocols')) return
    arr = m_array(d, 'protocols')
    do i = 1, arr_count(arr)
      if (len(val_text(arr_item(arr, i))) > 0) then
        protocols_present = .true.; return
      end if
    end do
  end function protocols_present

  ! §4.5: is a declared negotiation list PRESENT and DISJOINT from our single supported
  ! value? A present-but-EMPTY array rejects; an ABSENT field defaults to include (skip).
  logical function negotiation_disjoint(params, key, supported)
    type(entity_t),   intent(in) :: params
    character(len=*), intent(in) :: key, supported
    type(ecf_value_t) :: d, arr
    integer :: i
    negotiation_disjoint = .false.
    if (.not. params%present) return
    d = ent_data_map(params)
    if (.not. m_has(d, key)) return
    arr = m_array(d, key)
    do i = 1, arr_count(arr)
      if (val_text(arr_item(arr, i)) == supported) return   ! supported value present
    end do
    negotiation_disjoint = .true.
  end function negotiation_disjoint

  function connect_hello(slot, env) result(oc)
    integer,          intent(in) :: slot
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, params
    type(ecf_value_t) :: hm
    integer(int8) :: nonce(32)
    exec = env%root
    if (c_estab(slot)) then; oc = out_err(409, 'connection_already_established', ''); return; end if
    ! §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a HALF-OPEN
    ! connection (hello done, authenticate not yet) is an operation we implement arriving
    ! in a state that forbids it — the same class as connection_already_established
    ! above, taking the same 409. A half-open connection is NOT established, so the guard
    ! above cannot reach it; §4.7 names this gap explicitly because two adjacent rules
    ! each look like they cover it and neither does.
    if (c_has_nonce(slot)) then; oc = out_err(409, 'connection_sequence_error', ''); return; end if
    params = ent_entity_field(exec, 'params')
    ! §4.5 negotiation: reject a hello with no common hash format / no mutually-verifiable
    ! key type at the canonical earliest reject point (hello), per §4.7.
    if (negotiation_disjoint(params, 'hash_formats', 'ecfv1-sha256')) then
      oc = out_err(400, 'incompatible_hash_format', ''); return
    end if
    if (negotiation_disjoint(params, 'key_types', 'ed25519')) then
      oc = out_err(400, 'unsupported_key_type', ''); return
    end if
    ! §4.5 mutual verifiability, the direction that is NOT the array. `key_types` is an
    ! ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in its `peer_id` —
    ! so a hello may advertise a perfectly good accept-set and still name an identity we
    ! cannot verify. Checking only the array leaves that MUST unenforced at hello, which
    ! is where §4.5 wants it; authenticate catches it one leg later, which is conformant
    ! but non-canonical. An UNPARSEABLE peer_id is left alone (peer_id_key_type answers
    ! < 0): that is a malformed field, not a key_type we lack.
    if (params%present) then
      block
        character(len=:), allocatable :: hpid
        integer(int64) :: hello_kt
        hpid = ent_text(params, 'peer_id')
        if (len(hpid) > 0) then
          hello_kt = peer_id_key_type(hpid)
          if (hello_kt >= 0 .and. hello_kt /= 1_int64) then
            oc = out_err(400, 'unsupported_key_type', ''); return
          end if
        end if
      end block
    end if
    ! §4.5 `protocols` — the one negotiated field Required with NO default, so there is
    ! no floor to fall back to, and its two failure modes carry different codes on
    ! purpose (§4.5 table row / §4.7 row 1):
    !
    !   absent or empty     -> 400 invalid_request       (a malformed hello)
    !   non-empty, disjoint -> 400 incompatible_protocol (we compared)
    !
    ! "a caller that named no version cannot be told the comparison failed" — the
    ! remedies differ (send the field vs change the version) and §4.7 exists so the code
    ! selects the remedy. The vocabulary is §8.4's protocol version identifiers, today
    ! the single entity-core/1.0.
    !
    ! ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no precedence
    ! between the three, so a hello disjoint in more than one dimension may be refused on
    ! any of them — but the choice is OBSERVABLE, and the reference peer refuses
    ! key_types first. Checking protocols first is equally spec-legal and makes
    ! AGILITY-UNKNOWN-1 answer incompatible_protocol, because that probe's own hello
    ! carries protocols ["entity-core/v7"] — a spec-line name, not a §8.4 identifier
    ! (F56).
    if (.not. protocols_present(params)) then
      oc = out_err(400, 'invalid_request', 'hello: protocols absent or empty'); return
    end if
    if (negotiation_disjoint(params, 'protocols', 'entity-core/1.0')) then
      oc = out_err(400, 'incompatible_protocol', ''); return
    end if
    if (params%present) c_hello_pid(slot) = ent_text(params, 'peer_id')
    nonce = peer_random_bytes(32)
    c_nonce(:, slot) = nonce
    c_has_nonce(slot) = .true.
    hm = hello_map(nonce)
    oc = out_ok0(ent_make('system/protocol/connect/hello', hm))
  end function connect_hello

  function hello_map(nonce) result(hm)
    integer(int8), intent(in) :: nonce(:)
    type(ecf_value_t) :: hm
    hm = v_map_empty()
    hm = v_map_put(hm, 'peer_id', v_text(g_local))
    hm = v_map_put(hm, 'nonce', v_bytes(nonce))
    hm = v_map_put(hm, 'protocols', v_text_array('entity-core/1.0'))
    hm = v_map_put(hm, 'timestamp', v_uint(cap_now_ms()))
    hm = v_map_put(hm, 'hash_formats', v_text_array('ecfv1-sha256'))
    hm = v_map_put(hm, 'key_types', v_text_array('ed25519'))
  end function hello_map

  function connect_authenticate(slot, env) result(oc)
    integer,          intent(in) :: slot
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, auth, sgn, remote_peer
    type(ecf_value_t) :: grants, gm
    type(minted_t)  :: m
    integer(int8), allocatable :: pub(:), echoed(:), sb(:), issued(:)
    character(len=:), allocatable :: kt, claimed, hello_pid
    logical :: sig_ok
    exec = env%root
    ! RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
    ! single-use nonce. The anti-replay property is the MUST and the
    ! mechanism (established-state tracking) is impl-defined, but the
    ! STATUS is pinned to 401 invalid_nonce — a 409 state-conflict
    ! under-signals the replay.
    if (c_estab(slot)) then; oc = out_err(401, 'invalid_nonce', ''); return; end if
    if (.not. c_has_nonce(slot)) then; oc = out_err(401, 'invalid_nonce', ''); return; end if
    auth = ent_entity_field(exec, 'params')
    if (.not. auth%present) then; oc = out_err(401, 'authentication_failed', ''); return; end if
    kt = ent_text(auth, 'key_type')
    if (len(kt) > 0 .and. kt /= 'ed25519') then; oc = out_err(400, 'unsupported_key_type', ''); return; end if
    pub = ent_bytes(auth, 'public_key')
    if (size(pub) > 0 .and. size(pub) /= 32) then; oc = out_err(400, 'unsupported_key_type', ''); return; end if
    ! AGILITY-UNKNOWN-1 (§7.1): a claimed peer_id encoding an unsupported key_type (e.g.
    ! 0xFD) MUST reject with 400 unsupported_key_type here, not fall through to a downstream
    ! 401 identity_mismatch (peer_id_of_pubkey re-encodes under ed25519). See §4.5/§4.7.
    claimed = ent_text(auth, 'peer_id')
    if (len(claimed) > 0) then
      block
        integer(int64) :: claimed_kt
        claimed_kt = peer_id_key_type(claimed)
        if (claimed_kt >= 0 .and. claimed_kt /= 1_int64) then
          oc = out_err(400, 'unsupported_key_type', ''); return
        end if
      end block
    end if
    echoed = ent_bytes(auth, 'nonce')
    allocate(issued(32)); issued = c_nonce(:, slot)
    block
      logical :: nonce_ok
      nonce_ok = (size(echoed) == 32)
      if (nonce_ok) nonce_ok = all(echoed == issued)
      if (.not. nonce_ok) then; oc = out_err(401, 'invalid_nonce', ''); return; end if
    end block
    if (size(pub) == 0) then; oc = out_err(401, 'authentication_failed', ''); return; end if
    sgn = cap_find_signature(ent_hash(auth), env%inc)
    sig_ok = .false.
    if (sgn%present) then
      sb = ent_bytes(sgn, 'signature')
      if (size(sb) == 64) then
        block
          type(entity_t) :: sp
          sp = peer_entity_of_pubkey(pub)
          sig_ok = id_verify_signature(sgn, sp)
        end block
      end if
    end if
    if (.not. sig_ok) then; oc = out_err(401, 'authentication_failed', ''); return; end if
    claimed = ent_text(auth, 'peer_id')
    if (len(claimed) > 0 .and. claimed /= peer_id_of_pubkey(pub)) then; oc = out_err(401, 'identity_mismatch', ''); return; end if
    hello_pid = trim(c_hello_pid(slot))
    if (len(hello_pid) > 0 .and. len(claimed) > 0 .and. hello_pid /= claimed) then
      oc = out_err(401, 'identity_mismatch', ''); return
    end if
    remote_peer = peer_entity_of_pubkey(pub)
    grants = derive_seed_grants(remote_peer, peer_id_of_pubkey(pub))
    m = mint_token(ent_hash(remote_peer), grants, null_hash())
    c_estab(slot) = .true.
    gm = v_map_put(v_map_empty(), 'token', v_bytes(ent_hash(m%token)))
    oc = out_ok(ent_make('system/capability/grant', gm), cap_included(m))
  end function connect_authenticate

  ! ── §6.3 tree ──
  function hnd_tree(operation, env) result(oc)
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    if (operation == 'get') then; oc = tree_get(env)
    else if (operation == 'put') then; oc = tree_put(env)
    else; oc = out_err(501, 'unsupported_operation', operation); end if
  end function hnd_tree

  function exec_resource_target(exec) result(t)
    type(entity_t), intent(in) :: exec
    character(len=:), allocatable :: t
    type(ecf_value_t) :: r
    type(str_t), allocatable :: targets(:)
    t = ''
    r = ent_map_field(exec, 'resource')
    if (r%vkind /= EV_MAP) return
    targets = text_list(m_array(r, 'targets'))
    if (size(targets) > 0) t = targets(1)%s
  end function exec_resource_target

  function tree_get(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, e, params
    character(len=:), allocatable :: target, path, mode
    logical :: invalid
    exec = env%root
    target = exec_resource_target(exec)
    if (len(target) > 0 .and. .not. path_flex_ok(target)) then; oc = out_err(400, 'invalid_path', target); return; end if
    if (len(target) == 0) then; oc = tree_listing('/' // g_local // '/'); return; end if
    if (target(len(target):len(target)) == '/') then
      call cap_canonicalize(g_local, target, path, invalid)
      oc = tree_listing(path); return
    end if
    call cap_canonicalize(g_local, target, path, invalid)
    e = store_get_at(g_store, path)
    if (.not. e%present) then; oc = out_err(404, 'not_found', path); return; end if
    params = ent_entity_field(exec, 'params')
    mode = ''
    if (params%present) mode = ent_text(params, 'mode')
    if (mode == 'hash') then
      oc = out_ok0(ent_make('system/hash', v_map_put(v_map_empty(), 'hash', v_bytes(ent_hash(e)))))
      return
    end if
    oc = out_ok0(e)
  end function tree_get

  ! §6.3's `put` admission ladder (normative, 0.8.2.11).
  !
  ! `put` is a RECEIPT path: the submitter authors the entity, the peer validates what
  ! it received (§1.8 item 1) and MUST NOT author a submitted entity's content_hash on
  ! the submitter's behalf. Two ordered steps:
  !
  !   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any CBOR
  !      value; null is a legal payload), and a `content_hash` that is a well-formed
  !      system/hash whose total byte length matches its format code (§1.2). Any failure
  !      -> 400 invalid_request. A well-formed hash naming a format code this peer cannot
  !      VERIFY is the separate §1.2 ingest-dispatch case -> 400
  !      unsupported_content_hash_format. This peer's entity carries a fixed
  !      HASH_LEN-byte hash and hashes through the SHA-256 FFI floor, so 0x00 is the
  !      whole verifiable set here.
  !   2. HASH — carried content_hash vs content_hash({type, data}) -> 400 hash_mismatch.
  !
  ! Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's inputs
  ! are exactly what step 1 establishes, so a submission that is both malformed and
  ! mis-hashed is step 1's and answers invalid_request.
  !
  ! Structural admission is not semantic validation: `data` is never checked against the
  ! type named by `type`.
  subroutine admit_put(v, e, admitted, oc)
    type(ecf_value_t), intent(in)  :: v
    type(entity_t),    intent(out) :: e
    logical,           intent(out) :: admitted
    type(outcome_t),   intent(out) :: oc
    character(len=:), allocatable :: etype
    type(ecf_value_t) :: data
    integer(int8), allocatable :: carried(:)
    integer :: i, shift, consumed
    integer(int64) :: code
    logical :: done
    type(entity_t) :: computed
    admitted = .false.
    if (v%vkind /= EV_MAP) then
      oc = out_err(400, 'invalid_request', 'put: entity is not a map'); return
    end if
    etype = m_text(v, 'type')
    if (len(etype) == 0) then
      oc = out_err(400, 'invalid_request', 'put: entity.type absent, empty or not a text string'); return
    end if
    ! Presence, not truthiness: a CBOR null is a legal `data` payload, so m_has is the
    ! presence predicate rather than a kind test.
    if (.not. m_has(v, 'data')) then
      oc = out_err(400, 'invalid_request', 'put: entity.data absent'); return
    end if
    data = m_get(v, 'data')
    carried = m_bytes(v, 'content_hash')
    if (size(carried) == 0) then
      oc = out_err(400, 'invalid_request', 'put: entity.content_hash absent or not a byte string'); return
    end if
    ! Leading multicodec LEB128 format-code varint (§7.3).
    code = 0_int64; shift = 0; consumed = 0; done = .false.
    do i = 1, size(carried)
      code = code + int(iand(int(carried(i)), 127), int64) * (2_int64 ** shift)
      consumed = consumed + 1
      if (iand(int(carried(i)), 128) == 0) then; done = .true.; exit; end if
      shift = shift + 7
      if (shift >= 63) exit
    end do
    if (.not. done) then
      oc = out_err(400, 'invalid_request', 'put: entity.content_hash is not a well-formed system/hash'); return
    end if
    ! §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
    ! invalid_request: the shape is fine, the algorithm is what we lack.
    if (code /= 0_int64) then
      oc = out_err(400, 'unsupported_content_hash_format', 'put: unsupported content_hash_format'); return
    end if
    if (size(carried) /= consumed + 32) then
      oc = out_err(400, 'invalid_request', 'put: content_hash length does not match its format code'); return
    end if
    computed = ent_make(etype, data)
    if (.not. all(computed%hash == carried)) then
      oc = out_err(400, 'hash_mismatch', 'put: content_hash does not match content_hash({type, data})'); return
    end if
    ! The carried hash IS the entity's address. At the only code this peer verifies
    ! (0x00) the computed value and the carried bytes are the same 33 bytes, so binding
    ! the verified entity binds the submitted address rather than an authored one.
    e = computed
    admitted = .true.
  end subroutine admit_put

  function tree_put(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, params, entity
    type(ecf_value_t) :: raw_entity
    character(len=:), allocatable :: target, path, current
    integer(int8), allocatable :: expected(:)
    logical :: invalid, cas_ok, has_raw, admitted
    exec = env%root
    target = exec_resource_target(exec)
    if (len(target) == 0) then; oc = out_err(400, 'ambiguous_resource', 'tree: missing resource target'); return; end if
    if (.not. path_flex_ok(target)) then; oc = out_err(400, 'invalid_path', target); return; end if
    call cap_canonicalize(g_local, target, path, invalid)
    params = ent_entity_field(exec, 'params')
    raw_entity%vkind = EV_ABSENT
    has_raw = .false.
    allocate(expected(0))
    if (params%present) then
      has_raw = m_has(ent_data_map(params), 'entity')
      if (has_raw) raw_entity = ent_field(params, 'entity')
      expected = ent_bytes(params, 'expected_hash')
    end if
    current = store_hash_at(g_store, path)
    if (size(expected) == 0) then; cas_ok = .true.
    else if (hash_is_zero(expected)) then; cas_ok = (len(current) == 0)
    else; cas_ok = (len(current) > 0 .and. current == hexlc(expected)); end if
    if (.not. cas_ok) then; oc = out_err(409, 'hash_mismatch', path); return; end if
    if (.not. has_raw) then; oc = out_err(400, 'unexpected_params', 'put: missing entity'); return; end if
    call admit_put(raw_entity, entity, admitted, oc)
    if (.not. admitted) return
    call store_bind(g_store, path, entity)
    oc = out_ok0(ent_make('system/hash', v_map_put(v_map_empty(), 'hash', v_bytes(ent_hash(entity)))))
  end function tree_put

  function tree_listing(path) result(oc)
    character(len=*), intent(in) :: path
    type(outcome_t) :: oc
    type(listing_row_t), allocatable :: rows(:)
    type(ecf_value_t) :: em, led, lm
    type(entity_t) :: me
    integer :: i, count
    integer(int8), allocatable :: hb(:)
    rows = store_listing(g_store, path)
    em = v_map_empty()
    count = 0
    do i = 1, size(rows)
      if (len(rows(i)%hashhex) > 0 .and. .not. rows(i)%has_children) then
        hb = hex_to_bytes(rows(i)%hashhex)
        me = store_get_by_hash(g_store, hb)
        if (me%present) then
          if (ent_type(me) == 'system/deletion-marker') cycle
        end if
      end if
      led = v_map_empty()
      led = v_map_put(led, 'has_children', v_bool(rows(i)%has_children))
      if (len(rows(i)%hashhex) > 0) led = v_map_put(led, 'hash', v_bytes(hex_to_bytes(rows(i)%hashhex)))
      em = v_map_put(em, rows(i)%seg, ent_to_cbor(ent_make('system/tree/listing-entry', led)))
      count = count + 1
    end do
    lm = v_map_empty()
    lm = v_map_put(lm, 'path', v_text(path))
    lm = v_map_put(lm, 'entries', em)
    lm = v_map_put(lm, 'count', v_uint(int(count, int64)))
    lm = v_map_put(lm, 'offset', v_uint(0_int64))
    oc = out_ok0(ent_make('system/tree/listing', lm))
  end function tree_listing

  ! §1.4 path validity (no NUL, no empty/./.. segments; abs paths peer-rooted).
  logical function path_flex_ok(target)
    character(len=*), intent(in) :: target
    character(len=:), allocatable :: rest, body, first, seg
    integer :: slash
    logical :: abs_ok, is_abs
    path_flex_ok = .false.
    if (index(target, achar(0)) > 0) return
    is_abs = .false.
    if (len(target) >= 1) then; if (target(1:1) == '/') is_abs = .true.; end if
    if (is_abs) then
      rest = target(2:)
      slash = index(rest, '/')
      if (slash == 0) then; abs_ok = cap_is_peer_id(rest); body = ''
      else; first = rest(1:slash-1); abs_ok = cap_is_peer_id(first); body = rest(slash+1:); end if
    else
      abs_ok = .true.; body = target
    end if
    if (.not. abs_ok) return
    if (len(body) > 0) then
      if (body(len(body):len(body)) == '/') body = body(1:len(body)-1)
    end if
    do while (len(body) > 0)
      slash = index(body, '/')
      if (slash == 0) then; seg = body; body = ''
      else; seg = body(1:slash-1); body = body(slash+1:); end if
      if (len(seg) == 0 .or. seg == '.' .or. seg == '..') return
    end do
    path_flex_ok = .true.
  end function path_flex_ok

  ! ── §6.2 handlers (register/unregister) — minimal ──
  function hnd_handlers(operation, env) result(oc)
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    if (operation == 'register') then; oc = handlers_register(env)
    else if (operation == 'unregister') then; oc = handlers_unregister(env)
    else; oc = out_err(501, 'unsupported_operation', operation); end if
  end function hnd_handlers

  function register_pattern(exec) result(p)
    type(entity_t), intent(in) :: exec
    character(len=:), allocatable :: p, target
    character(len=*), parameter :: pfx = 'system/handler/'
    p = ''
    target = exec_resource_target(exec)
    if (len(target) <= len(pfx)) return
    if (target(1:len(pfx)) /= pfx) return
    p = target(len(pfx)+1:)
  end function register_pattern

  ! §6.2: user-installed handlers MUST NOT register at system/* paths.
  function is_reserved_system_pattern(pattern) result(reserved)
    character(len=*), intent(in) :: pattern
    logical :: reserved
    character(len=*), parameter :: pfx = 'system/'
    reserved = .false.
    if (pattern == 'system') then; reserved = .true.; return; end if
    if (len(pattern) < len(pfx)) return
    if (pattern(1:len(pfx)) == pfx) reserved = .true.
  end function is_reserved_system_pattern

  function handlers_register(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, req
    type(ecf_value_t) :: manifest, operations, hp, im, rm
    type(minted_t)  :: m
    character(len=:), allocatable :: pattern, name, expr_path, interface_rel
    type(ecf_value_t) :: grant_scope
    exec = env%root
    pattern = register_pattern(exec)
    if (len(pattern) == 0) then; oc = register_pattern_error(exec); return; end if
    if (is_reserved_system_pattern(pattern)) then
      oc = out_err(403, 'forbidden_pattern', &
        '§6.2: user-installed handlers MUST NOT register at system/* paths: ' // pattern)
      return
    end if
    req = ent_entity_field(exec, 'params')
    if (.not. req%present) then; oc = out_err(400, 'unexpected_params', 'register: missing params'); return; end if
    if (ent_type(req) /= 'system/handler/register-request') then; oc = out_err(400, 'unexpected_params', 'register expects register-request'); return; end if
    manifest = ent_map_field(req, 'manifest')
    if (manifest%vkind /= EV_MAP) manifest = v_map_empty()
    name = m_text(manifest, 'name')
    if (len(name) == 0) name = pattern
    operations = m_submap(manifest, 'operations')
    if (operations%vkind /= EV_MAP) operations = v_map_empty()
    expr_path = m_text(manifest, 'expression_path')
    grant_scope = m_array(ent_data_map(req), 'requested_scope')
    interface_rel = 'system/handler/' // pattern
    hp = v_map_put(v_map_empty(), 'interface', v_text(interface_rel))
    if (len(expr_path) > 0) hp = v_map_put(hp, 'expression_path', v_text(expr_path))
    call store_bind(g_store, peer_abs(pattern), ent_make('system/handler', hp))
    m = mint_token(g_ident%id_hash, grant_scope, null_hash())
    call store_bind(g_store, peer_abs('system/capability/grants/' // pattern), m%token)
    call store_bind(g_store, peer_abs('system/signature/' // hexlc(ent_hash(m%token))), m%sig)
    im = v_map_put(v_map_put(v_map_empty(), 'pattern', v_text(pattern)), 'name', v_text(name))
    im = v_map_put(im, 'operations', operations)
    call store_bind(g_store, peer_abs(interface_rel), ent_make('system/handler/interface', im))
    rm = v_map_put(v_map_put(v_map_empty(), 'pattern', v_text(pattern)), 'grant', ent_data(m%token))
    oc = out_ok0(ent_make('system/handler/register-result', rm))
  end function handlers_register

  function register_pattern_error(exec) result(oc)
    type(entity_t), intent(in) :: exec
    type(outcome_t) :: oc
    if (len(exec_resource_target(exec)) == 0) then
      oc = out_err(400, 'ambiguous_resource', 'register/unregister require exactly one resource target')
    else
      oc = out_err(400, 'invalid_resource', 'resource target MUST be system/handler/{pattern}')
    end if
  end function register_pattern_error

  function handlers_unregister(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, g
    character(len=:), allocatable :: pattern
    exec = env%root
    pattern = register_pattern(exec)
    if (len(pattern) == 0) then; oc = register_pattern_error(exec); return; end if
    g = store_get_at(g_store, peer_abs('system/capability/grants/' // pattern))
    if (g%present) then
      call store_unbind(g_store, peer_abs('system/signature/' // hexlc(ent_hash(g))))
      call store_unbind(g_store, peer_abs('system/capability/grants/' // pattern))
    end if
    call store_unbind(g_store, peer_abs(pattern))
    call store_unbind(g_store, peer_abs('system/handler/' // pattern))
    oc = out_ok0(wire_empty_params())
  end function handlers_unregister

  ! ── system/type:validate (minimal) ──
  function hnd_type(operation, env) result(oc)
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: exec, req, subject, type_def
    type(ecf_value_t) :: fields, subj_data, vm, fk, fv, spec
    character(len=:), allocatable :: type_name, fname
    logical :: valid, optional, present
    integer :: i
    if (operation /= 'validate') then; oc = out_err(501, 'unsupported_operation', operation); return; end if
    exec = env%root
    req = ent_entity_field(exec, 'params')
    if (.not. req%present) then; oc = out_err(400, 'invalid_params', 'validate requires a params entity'); return; end if
    subject = ent_entity_field(req, 'entity')
    if (.not. subject%present) then; oc = out_err(400, 'unexpected_params', 'validate-request missing entity'); return; end if
    type_name = ent_text(req, 'type_path')
    if (len(type_name) == 0) type_name = ent_type(subject)
    type_def = store_get_at(g_store, peer_abs('system/type/' // type_name))
    if (.not. type_def%present) then
      oc = out_ok0(ent_make('system/type/validate-result', v_map_put(v_map_empty(), 'valid', v_bool(.false.))))
      return
    end if
    fields = ent_map_field(type_def, 'fields')
    subj_data = ent_data_map(subject)
    valid = .true.
    if (fields%vkind == EV_MAP .and. associated(fields%items)) then
      do i = 1, size(fields%items)/2
        fk = fields%items(2*i-1); fv = fields%items(2*i)
        if (.not. val_is_text(fk)) cycle
        fname = val_text(fk)
        spec = fv
        optional = .false.
        if (val_is_map(spec)) optional = m_bool(spec, 'optional')
        present = m_has(subj_data, fname)
        if (.not. optional .and. .not. present) valid = .false.
      end do
    end if
    vm = v_map_put(v_map_empty(), 'valid', v_bool(valid))
    oc = out_ok0(ent_make('system/type/validate-result', vm))
  end function hnd_type

  ! ── §6.2 capability ──
  function hnd_capability(operation, env, caller_cap) result(oc)
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(entity_t),   intent(in) :: caller_cap
    type(outcome_t) :: oc
    select case (operation)
    case ('request');   oc = cap_request(env, caller_cap)
    case ('delegate');  oc = cap_delegate(env, caller_cap)
    case ('revoke');    oc = cap_revoke(env)
    case ('configure'); oc = cap_configure(env)
    case default;       oc = out_err(501, 'unsupported_operation', operation)
    end select
  end function hnd_capability

  function req_grants(params) result(g)
    type(entity_t), intent(in) :: params
    type(ecf_value_t) :: g
    if (params%present) then; g = m_array(ent_data_map(params), 'grants'); else; g = v_arr_empty(); end if
  end function req_grants

  function cap_request(env, caller_cap) result(oc)
    type(envelope_t), intent(in) :: env
    type(entity_t),   intent(in) :: caller_cap
    type(outcome_t) :: oc
    type(entity_t)  :: params
    integer(int8), allocatable :: author(:)
    params = ent_entity_field(env%root, 'params')
    author = ent_bytes(env%root, 'author')
    if (size(author) == 0) then; oc = out_err(403, 'capability_denied', ''); return; end if
    oc = cap_mint_bounded(env%inc, g_store, caller_cap, params, req_grants(params), author, null_hash())
  end function cap_request

  function cap_delegate(env, caller_cap) result(oc)
    type(envelope_t), intent(in) :: env
    type(entity_t),   intent(in) :: caller_cap
    type(outcome_t) :: oc
    type(entity_t)  :: params
    integer(int8), allocatable :: author(:), ph(:)
    params = ent_entity_field(env%root, 'params')
    author = ent_bytes(env%root, 'author')
    allocate(ph(0))
    if (params%present) ph = ent_bytes(params, 'parent')
    if (size(ph) == 0) then; oc = out_err(400, 'unexpected_params', 'delegate: parent required'); return; end if
    if (hash_is_zero(ph)) then; oc = out_err(400, 'unexpected_params', 'delegate: zero parent'); return; end if
    if (.not. (size(author) > 0 .and. hash_eq(g_ident%id_hash, author))) then
      oc = out_err(501, 'unsupported_operation', 'delegate: same-peer-only in v1'); return
    end if
    oc = cap_mint_bounded(env%inc, g_store, caller_cap, params, req_grants(params), author, ph)
  end function cap_delegate

  ! fold one DEFINED term into the running §5.6 MIN_DEFINED ceiling.
  subroutine fold_min(defined, term, acc, have)
    logical,        intent(in)    :: defined
    integer(int64), intent(in)    :: term
    integer(int64), intent(inout) :: acc
    logical,        intent(inout) :: have
    if (.not. defined) return
    if ((.not. have) .or. term < acc) then; acc = term; have = .true.; end if
  end subroutine fold_min

  function cap_mint_bounded(inc, store, caller_cap, params, rg, grantee_hash, parent) result(oc)
    type(entity_t),    intent(in) :: inc(:)
    type(store_t),     intent(in) :: store
    type(entity_t),    intent(in) :: caller_cap, params
    type(ecf_value_t), intent(in) :: rg
    integer(int8),     intent(in) :: grantee_hash(:), parent(:)
    type(outcome_t) :: oc
    type(ecf_value_t) :: parent_grants, c, pj, gm
    type(minted_t) :: m
    type(entity_t) :: pt
    integer(int64) :: created_at, ceiling, term, ttl
    logical :: have_ceiling, pterm, pttl
    integer :: i, j
    logical :: bounded, covered
    bounded = .false.
    if (caller_cap%present) then
      parent_grants = cap_grants_of_token(caller_cap)
      bounded = .true.
      do i = 1, arr_count(rg)
        c = arr_item(rg, i)
        covered = .false.
        do j = 1, arr_count(parent_grants)
          pj = arr_item(parent_grants, j)
          if (cap_grant_subset_local(g_local, c, pj)) then; covered = .true.; exit; end if
        end do
        if (.not. covered) then; bounded = .false.; exit; end if
      end do
    end if
    if (.not. bounded) then; oc = out_err(403, 'scope_exceeds_authority', ''); return; end if

    ! §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
    ! convert the duration term against that same instant.
    !
    ! Note what this is NOT: an authorization decision. An over-long ttl_ms from a bounded
    ! caller MINTS a clamped token and returns 200 -- "rejecting it is non-conformant"
    ! (§5.6). The bound exists because `request` mints a ROOT token (parent: null), so
    ! §5.6's parent-child attenuation never reaches it; without this clamp, temporal
    ! attenuation is the one dimension a requester could escape, and policy withdrawal
    ! would have no bounded latency.
    created_at = cap_now_ms()
    have_ceiling = .false.; ceiling = 0_int64
    if (size(parent) > 0) then                                   ! absolute
      pt = cap_resolve(inc, store, parent)
      if (pt%present) then
        call ent_uint(pt, 'expires_at', term, pterm)
        call fold_min(pterm, term, ceiling, have_ceiling)
      end if
    end if
    if (caller_cap%present) then                                 ! absolute
      call ent_uint(caller_cap, 'expires_at', term, pterm)
      call fold_min(pterm, term, ceiling, have_ceiling)
    end if
    if (params%present) then                                     ! duration
      call ent_uint(params, 'ttl_ms', ttl, pttl)
      if (pttl) then
        call cap_add_ttl(created_at, ttl, term, pterm)
        call fold_min(pterm, term, ceiling, have_ceiling)
      end if
    end if

    m = mint_token_at(created_at, grantee_hash, rg, parent, ceiling, have_ceiling)
    gm = v_map_put(v_map_empty(), 'token', v_bytes(ent_hash(m%token)))
    oc = out_ok(ent_make('system/capability/grant', gm), cap_included(m))
  end function cap_mint_bounded

  function cap_revoke(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: params, marker
    type(ecf_value_t) :: rm
    integer(int8), allocatable :: token_h(:)
    params = ent_entity_field(env%root, 'params')
    allocate(token_h(0))
    if (params%present) token_h = ent_bytes(params, 'token')
    if (size(token_h) == 0) then; oc = out_err(400, 'unexpected_params', 'revoke: missing token'); return; end if
    if (hash_is_zero(token_h)) then; oc = out_err(400, 'unexpected_params', 'revoke: zero token'); return; end if
    rm = v_map_put(v_map_put(v_map_empty(), 'token', v_bytes(token_h)), 'revoked_at', v_uint(cap_now_ms()))
    marker = ent_make('system/capability/revocation', rm)
    call store_bind(g_store, '/' // g_local // '/system/capability/revocations/' // hexlc(token_h), marker)
    oc = out_ok0(wire_empty_params())
  end function cap_revoke

  function cap_configure(env) result(oc)
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t)  :: params
    character(len=:), allocatable :: pp
    logical :: is_hex
    params = ent_entity_field(env%root, 'params')
    pp = ''
    if (params%present) pp = ent_text(params, 'peer_pattern')
    if (len(pp) == 0) then; oc = out_err(400, 'unexpected_params', 'configure: missing peer_pattern'); return; end if
    is_hex = (len(pp) == 66 .and. is_hexstr(pp))
    if (.not. (pp == 'default' .or. is_hex .or. cap_is_peer_id(pp))) then; oc = out_err(400, 'invalid_peer_pattern', pp); return; end if
    call store_bind(g_store, '/' // g_local // '/system/capability/policy/' // pp, params)
    oc = out_ok0(wire_empty_params())
  end function cap_configure

  logical function is_hexstr(s)
    character(len=*), intent(in) :: s
    integer :: i
    character :: c
    is_hexstr = .true.
    do i = 1, len(s)
      c = s(i:i)
      if (.not. ((c >= '0' .and. c <= '9') .or. (c >= 'a' .and. c <= 'f'))) then; is_hexstr = .false.; return; end if
    end do
  end function is_hexstr

  ! ── §7a conformance handlers ──
  function hnd_echo(operation, env) result(oc)
    character(len=*), intent(in) :: operation
    type(envelope_t), intent(in) :: env
    type(outcome_t) :: oc
    type(entity_t) :: p
    if (operation /= 'echo') then; oc = out_err(501, 'unsupported_operation', operation); return; end if
    p = ent_entity_field(env%root, 'params')
    if (.not. p%present) then; oc = out_err(400, 'invalid_params', 'echo requires params'); return; end if
    oc = out_ok0(p)
  end function hnd_echo

  ! §6.13(b) handler-initiated outbound dispatch, exercised by the §7a.2a validate probe.
  ! Originates an outbound EXECUTE back over the SAME inbound connection (the reentry seam)
  ! and pumps the single serve loop reentrantly until the reply correlates by request_id
  ! (§6.11). Nested calls (concurrent reentry, t1_2) recurse on the same pump — safe because
  ! each level awaits its own unique 'out-N' rid in the per-connection pending table.
  function hnd_dispatch_outbound(slot, operation, env, caller_cap, granter_peer) result(oc)
    integer,          intent(in) :: slot
    character(len=*), intent(in) :: operation, granter_peer
    type(envelope_t), intent(in) :: env
    type(entity_t),   intent(in) :: caller_cap
    type(outcome_t) :: oc
    type(entity_t)    :: params, rcap, rgranter, rcap_sig, inner, exec, exec_sig
    type(ecf_value_t) :: value, inner_data, resource, om, resv
    type(envelope_t)  :: out_env, resp
    type(entity_t), allocatable :: inc(:)
    character(len=:), allocatable :: target, op, rid
    integer(int8), allocatable :: frame(:), payload(:)
    logical :: ok, found, has_val
    integer :: io, status

    if (operation /= 'dispatch') then; oc = out_err(501, 'unsupported_operation', operation); return; end if
    params = ent_entity_field(env%root, 'params')
    if (.not. params%present) then
      oc = out_err(400, 'invalid_params', 'dispatch-outbound requires a params entity'); return
    end if
    target   = ent_text(params, 'target')
    op       = ent_text(params, 'operation')
    has_val  = m_has(ent_data_map(params), 'value')
    value    = ent_field(params, 'value')
    rcap     = ent_entity_field(params, 'reentry_capability')
    rgranter = ent_entity_field(params, 'reentry_granter')
    rcap_sig = ent_entity_field(params, 'reentry_cap_signature')
    if (len(target) == 0 .or. .not. has_val .or. .not. rcap%present &
        .or. .not. rgranter%present .or. .not. rcap_sig%present) then
      oc = out_err(400, 'invalid_params', 'dispatch-outbound requires value + reentry authority'); return
    end if
    ! §7a.1 generic relay: `value` is the downstream params data, forwarded VERBATIM.
    if (val_is_map(value)) then
      inner_data = value
    else
      inner_data = v_map_put(v_map_empty(), 'value', value)
    end if
    inner = ent_make('primitive/any', inner_data)
    ! the reentry connection IS the inbound connection this handler runs on.
    io = c_io(slot)
    if (io == 0) then; oc = out_err(503, 'no_outbound_seam', 'no live §6.11 reentry connection'); return; end if
    resource = wire_resource_target('system/handler/' // target)
    rid  = 'out-' // itoa(next_rid_ctr())
    exec = wire_make_execute(rid, target, op, inner, g_ident%id_hash, ent_hash(rcap), resource)
    exec_sig = id_sign(g_ident, exec)
    allocate(inc(5))
    inc(1) = rcap; inc(2) = rgranter; inc(3) = g_ident%peer_entity; inc(4) = rcap_sig; inc(5) = exec_sig
    out_env = env_make(exec, inc)
    ! send on the SAME connection + reentrant pump until the reply (§6.11 out-of-order demux).
    call tr_pending_register(rid)
    frame = wire_frame_of_envelope(out_env)
    call tr_send_frame(io, frame)
    call pump_until(rid, ok)
    if (.not. ok) then; oc = out_err(503, 'connection_broken', 'reentry connection lost'); return; end if
    call tr_pending_take(rid, payload, found)
    if (.not. found) then; oc = out_err(503, 'connection_broken', 'reentry response missing'); return; end if
    call wire_envelope_of_frame(payload, resp, ok)
    if (.not. ok) then; oc = out_err(502, 'protocol_error', 'reentry response malformed'); return; end if
    status = wire_response_status(resp)
    resv   = ent_field(resp%root, 'result')
    if (resv%vkind /= EV_MAP) resv = v_map_empty()
    om = v_map_put(v_map_empty(), 'status', v_uint(int(status, int64)))
    om = v_map_put(om, 'result', resv)
    oc = out_ok0(ent_make('primitive/any', om))
  end function hnd_dispatch_outbound

  ! ═══════════════ transport pump (serve + client) ═══════════════
  integer function peer_listen(port)
    integer, intent(in) :: port
    peer_listen = tr_listen(port)
  end function peer_listen

  subroutine peer_shutdown()
    call tr_shutdown()
  end subroutine peer_shutdown

  integer function conn_slot_of(io)
    integer, intent(in) :: io
    integer :: i
    conn_slot_of = 0
    do i = 1, MAXCONN
      if (c_io(i) == io) then; conn_slot_of = i; return; end if
    end do
  end function conn_slot_of

  integer function conn_open(io)
    integer, intent(in) :: io
    integer :: i
    conn_open = conn_slot_of(io)
    if (conn_open > 0) return
    do i = 1, MAXCONN
      if (c_io(i) == 0) then
        c_io(i) = io; c_estab(i) = .false.; c_has_nonce(i) = .false.; c_hello_pid(i) = ''
        conn_open = i; c_n = c_n + 1; return
      end if
    end do
  end function conn_open

  subroutine conn_close_io(io)
    integer, intent(in) :: io
    integer :: s
    s = conn_slot_of(io)
    if (s > 0) then; c_io(s) = 0; c_estab(s) = .false.; c_has_nonce(s) = .false. ; end if
  end subroutine conn_close_io

  subroutine on_frame(io, payload)
    integer,       intent(in) :: io
    integer(int8), intent(in) :: payload(:)
    character(len=:), allocatable :: root_type, rid
    logical :: is_response, ok, ok2, has_resp
    type(envelope_t) :: env, resp_env
    integer :: slot
    integer(int8), allocatable :: frame(:)
    call wire_peek(payload, root_type, rid, is_response, ok)
    if (.not. ok) return
    if (is_response) then
      call tr_pending_deliver(rid, payload)
      return
    end if
    if (root_type /= 'system/protocol/execute') return    ! §3.3: ignore other root types
    slot = conn_open(io)
    call wire_envelope_of_frame(payload, env, ok2)
    if (.not. ok2) then
      if (len(rid) > 0) then
        resp_env = env_make(wire_make_response(rid, 400, wire_error_result('non_canonical_ecf', '')), empty_ents())
        frame = wire_frame_of_envelope(resp_env)
        call tr_send_frame(io, frame)
      end if
      return
    end if
    call peer_dispatch(slot, env, resp_env, has_resp)
    if (has_resp) then
      frame = wire_frame_of_envelope(resp_env)
      call tr_send_frame(io, frame)
    end if
  end subroutine on_frame

  function empty_ents() result(e)
    type(entity_t), allocatable :: e(:)
    allocate(e(0))
  end function empty_ents

  subroutine send_413(io)
    integer, intent(in) :: io
    type(envelope_t) :: resp_env
    integer(int8), allocatable :: frame(:)
    ! §4.10(a): the net-shim signalled OVERSIZE before buffering the body; answer 413 and
    ! keep serving (request_id is unknown — the body was never read — so it is empty).
    resp_env = env_make(wire_make_response('', 413, wire_error_result('payload_too_large', '')), empty_ents())
    frame = wire_frame_of_envelope(resp_env)
    call tr_send_frame(io, frame)
  end subroutine send_413

  subroutine peer_serve()
    integer :: kind, id, plen, idummy
    integer(int8), allocatable :: payload(:)
    do
      call tr_poll(-1, kind, id, payload, plen)
      select case (kind)
      case (EV_ACCEPT);   idummy = conn_open(id)
      case (EV_CLOSED);   call conn_close_io(id)
      case (EV_OVERSIZE); call send_413(id)
      case (EV_FRAME);    call on_frame(id, payload)
      case default;       cycle                    ! EV_NONE (EINTR/spurious): keep serving,
                                                   ! never stop the persistent listener.
      end select
    end do
  end subroutine peer_serve

  ! ── initiator session (§4.4) ──
  integer function next_rid_ctr()
    g_out_ctr = g_out_ctr + 1
    next_rid_ctr = g_out_ctr
  end function next_rid_ctr

  function itoa(n) result(s)
    integer, intent(in) :: n
    character(len=:), allocatable :: s
    character(len=16) :: buf
    write(buf, '(i0)') n
    s = trim(buf)
  end function itoa

  function peer_dial(port) result(sess)
    integer, intent(in) :: port
    type(session_t) :: sess
    integer :: io
    io = tr_dial(port)
    if (io < 0) then; sess%ok = .false.; return; end if
    if (conn_open(io) < 0) then; sess%ok = .false.; return; end if
    sess%io = io
    sess%req_ctr = 0
    sess%ident = g_ident
    call handshake(sess)
  end function peer_dial

  ! send an envelope, pump the loop until its reply correlates by request_id (§6.11),
  ! return the response envelope (ok=.false. on connection loss).
  subroutine sess_send(sess, env, resp, ok)
    type(session_t),  intent(inout) :: sess
    type(envelope_t), intent(in)    :: env
    type(envelope_t), intent(out)   :: resp
    logical,          intent(out)   :: ok
    character(len=:), allocatable :: rid
    integer(int8), allocatable :: frame(:), payload(:)
    logical :: found
    rid = ent_text(env%root, 'request_id')
    call tr_pending_register(rid)
    frame = wire_frame_of_envelope(env)
    call tr_send_frame(sess%io, frame)
    call pump_until(rid, ok)
    if (.not. ok) return
    call tr_pending_take(rid, payload, found)
    if (.not. found) then; ok = .false.; return; end if
    call wire_envelope_of_frame(payload, resp, ok)
  end subroutine sess_send

  ! pump events until `rid` is delivered; ok=.false. on connection loss.
  subroutine pump_until(rid, ok)
    character(len=*), intent(in)  :: rid
    logical,          intent(out) :: ok
    integer :: kind, id, plen, idummy
    integer(int8), allocatable :: payload(:)
    do
      if (tr_pending_done(rid)) then; ok = .true.; return; end if
      call tr_poll(-1, kind, id, payload, plen)
      select case (kind)
      case (EV_ACCEPT);   idummy = conn_open(id)
      case (EV_CLOSED);   call conn_close_io(id)
      case (EV_OVERSIZE); call send_413(id)
      case (EV_FRAME);    call on_frame(id, payload)
      case default;       ok = .false.; return
      end select
    end do
  end subroutine pump_until

  ! §4.1 forward handshake: hello then authenticate.
  subroutine handshake(sess)
    type(session_t), intent(inout) :: sess
    type(entity_t)  :: hello, ex1, remote_hello, r1root
    type(entity_t)  :: auth, ex2, sig, r2root, grant, token, granter, cap_sig
    type(envelope_t) :: r1, r2
    type(ecf_value_t) :: hm, am, absent
    integer(int8), allocatable :: remote_nonce(:), token_h(:), granter_h(:)
    type(entity_t), allocatable :: inc0(:), inc2(:)
    logical :: ok
    absent%vkind = EV_ABSENT
    sess%ok = .false.
    ! hello
    hm = hello_map(peer_random_bytes(32))
    hello = ent_make('system/protocol/connect/hello', hm)
    sess%req_ctr = sess%req_ctr + 1
    ex1 = wire_make_execute('req-' // itoa(sess%req_ctr), 'system/protocol/connect', 'hello', hello, null_hash(), null_hash(), absent)
    allocate(inc0(0))
    call sess_send(sess, env_make(ex1, inc0), r1, ok)
    if (.not. ok) return
    if (wire_response_status(r1) /= 200) return
    remote_hello = wire_response_result(r1)
    sess%remote_peer_id = ent_text(remote_hello, 'peer_id')
    remote_nonce = ent_bytes(remote_hello, 'nonce')
    if (size(remote_nonce) == 0) return
    ! authenticate
    am = v_map_empty()
    am = v_map_put(am, 'peer_id', v_text(sess%ident%peer_id))
    am = v_map_put(am, 'public_key', v_bytes(sess%ident%pub))
    am = v_map_put(am, 'key_type', v_text('ed25519'))
    am = v_map_put(am, 'nonce', v_bytes(remote_nonce))
    auth = ent_make('system/protocol/connect/authenticate', am)
    sig = id_sign(sess%ident, auth)
    sess%req_ctr = sess%req_ctr + 1
    ex2 = wire_make_execute('req-' // itoa(sess%req_ctr), 'system/protocol/connect', 'authenticate', auth, null_hash(), null_hash(), absent)
    allocate(inc2(2)); inc2(1) = sess%ident%peer_entity; inc2(2) = sig
    call sess_send(sess, env_make(ex2, inc2), r2, ok)
    if (.not. ok) return
    if (wire_response_status(r2) /= 200) return
    grant = wire_response_result(r2)
    token_h = ent_bytes(grant, 'token')
    if (size(token_h) == 0) return
    token = env_included_get(r2, token_h)
    if (.not. token%present) return
    granter_h = ent_bytes(token, 'granter')
    granter = env_included_get(r2, granter_h)
    if (.not. granter%present) return
    cap_sig = cap_find_signature(ent_hash(token), r2%inc)
    if (.not. cap_sig%present) return
    sess%cap = token
    sess%granter = granter
    sess%cap_sig = cap_sig
    sess%ok = .true.
  end subroutine handshake

  function auth_included(sess, exec_sig) result(inc)
    type(session_t), intent(in) :: sess
    type(entity_t),  intent(in) :: exec_sig
    type(entity_t), allocatable :: inc(:)
    allocate(inc(5))
    inc(1) = sess%cap
    inc(2) = sess%granter
    inc(3) = sess%ident%peer_entity
    inc(4) = sess%cap_sig
    inc(5) = exec_sig
  end function auth_included

  function build_exec(sess, uri, operation, params, resource) result(env)
    type(session_t),   intent(inout) :: sess
    character(len=*),  intent(in) :: uri, operation
    type(entity_t),    intent(in) :: params
    type(ecf_value_t), intent(in) :: resource
    type(envelope_t) :: env
    type(entity_t)   :: exec, exec_sig
    sess%req_ctr = sess%req_ctr + 1
    exec = wire_make_execute('req-' // itoa(sess%req_ctr), uri, operation, params, &
                             sess%ident%id_hash, ent_hash(sess%cap), resource)
    exec_sig = id_sign(sess%ident, exec)
    env = env_make(exec, auth_included(sess, exec_sig))
  end function build_exec

  ! build+sign+send an authenticated EXECUTE; await the response.
  subroutine sess_execute(sess, uri, operation, params, resource, resp, ok)
    type(session_t),   intent(inout) :: sess
    character(len=*),  intent(in)  :: uri, operation
    type(entity_t),    intent(in)  :: params
    type(ecf_value_t), intent(in)  :: resource
    type(envelope_t),  intent(out) :: resp
    logical,           intent(out) :: ok
    call sess_send(sess, build_exec(sess, uri, operation, params, resource), resp, ok)
  end subroutine sess_execute

  ! fire WITHOUT awaiting (multiple in-flight -> §6.11 out-of-order demux). Returns the rid.
  function sess_execute_async(sess, uri, operation, params, resource) result(rid)
    type(session_t),   intent(inout) :: sess
    character(len=*),  intent(in) :: uri, operation
    type(entity_t),    intent(in) :: params
    type(ecf_value_t), intent(in) :: resource
    character(len=:), allocatable :: rid
    type(envelope_t) :: env
    integer(int8), allocatable :: frame(:)
    env = build_exec(sess, uri, operation, params, resource)
    rid = ent_text(env%root, 'request_id')
    call tr_pending_register(rid)
    frame = wire_frame_of_envelope(env)
    call tr_send_frame(sess%io, frame)
  end function sess_execute_async

  subroutine sess_await(rid, ok)
    character(len=*), intent(in)  :: rid
    logical,          intent(out) :: ok
    call pump_until(rid, ok)
  end subroutine sess_await

  subroutine sess_response(rid, resp, found)
    character(len=*), intent(in)  :: rid
    type(envelope_t), intent(out) :: resp
    logical,          intent(out) :: found
    integer(int8), allocatable :: payload(:)
    logical :: ok
    call tr_pending_take(rid, payload, found)
    if (.not. found) return
    call wire_envelope_of_frame(payload, resp, ok)
    found = ok
  end subroutine sess_response

end module entity_core_peer
