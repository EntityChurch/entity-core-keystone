! entity-core-protocol-fortran — test/s3_selftest.f90 (offline foundation self-test).
!
! Exercises the S3 peer-layer foundation with NO network: the content store + entity tree,
! materialized-entity content_hash + wire round-trip (§1.8 fidelity), L1 identity
! sign/verify, base64 keystore round-trip, and the full §5.2 capability verify-request
! chain on a hand-built authenticated envelope (A grants to B; B's request ALLOWs; a
! tampered signature DENIES). This is the accept-path coverage the rejection-only oracle
! categories cannot reach (the "conformance-green can be vacuous" lesson).
program s3_selftest
  use, intrinsic :: iso_fortran_env, only : int8, int64, output_unit
  use entity_core_status
  use entity_core_cbor
  use entity_core_val
  use entity_core_ent
  use entity_core_store
  use entity_core_identity
  use entity_core_capability
  use entity_core_wire
  use entity_core_keystore
  implicit none

  integer :: npass, nfail
  npass = 0; nfail = 0

  call test_keystore()
  call test_store()
  call test_entity_roundtrip()
  call test_sign_verify()
  call test_capability_chain()

  write(output_unit, '(a)') ''
  if (nfail > 0) then
    write(output_unit, '(a,i0,a,i0,a)') 'SELFTEST: FAIL (', npass, '/', npass+nfail, ')'
    stop 1
  end if
  write(output_unit, '(a,i0,a,i0,a)') 'SELFTEST: PASS (', npass, '/', npass+nfail, ')'

contains

  subroutine check(name, cond)
    character(len=*), intent(in) :: name
    logical,          intent(in) :: cond
    if (cond) then; npass = npass + 1; write(output_unit,'(a,a)') '  [PASS] ', name
    else; nfail = nfail + 1; write(output_unit,'(a,a)') '  [FAIL] ', name; end if
  end subroutine check

  subroutine test_keystore()
    integer(int8) :: seed(32), rt(32)
    character(len=:), allocatable :: b64, known
    integer(int8), allocatable :: dec(:)
    integer :: i
    do i = 1, 32; seed(i) = int(iand(i*7, 255), int8); end do
    b64 = b64_encode(seed)
    dec = b64_decode(b64)
    call check('base64 round-trip (32-byte seed)', size(dec) == 32)
    if (size(dec) == 32) then; rt = dec(1:32); call check('base64 preserves bytes', all(rt == seed)); end if
    known = b64_encode(keystore_seed_of_hexbyte('11'))
    call check('seed 0x11 x32 == known base64 ERER...', known(1:8) == 'ERERERER')
  end subroutine test_keystore

  subroutine test_store()
    type(store_t) :: s
    type(entity_t) :: a, b, got
    s = store_new()
    a = ent_make('primitive/string', v_text('alpha'))
    b = ent_make('primitive/string', v_text('beta'))
    call store_bind(s, '/x/a', a)
    call store_bind(s, '/x/b', b)
    got = store_get_at(s, '/x/a')
    call check('store bind/get round-trip', got%present .and. ent_type(got) == 'primitive/string')
    got = store_get_by_hash(s, ent_hash(b))
    call check('store get by hash', got%present)
    got = store_get_at(s, '/x/missing')
    call check('store miss -> absent', .not. got%present)
    call store_unbind(s, '/x/a')
    got = store_get_at(s, '/x/a')
    call check('store unbind', .not. got%present)
  end subroutine test_store

  subroutine test_entity_roundtrip()
    type(entity_t) :: e, dec
    type(ecf_value_t) :: wire, decoded
    integer(int8), allocatable :: bytes(:)
    integer :: consumed, stat
    type(ecf_value_t) :: m
    m = v_map_put(v_map_put(v_map_empty(), 'k', v_uint(42_int64)), 'name', v_text('z'))
    e = ent_make('system/peer', m)
    wire = ent_to_cbor(e)
    call cbor_encode(wire, bytes, stat)
    call check('entity wire encode ok', stat == EC_OK)
    call cbor_decode(bytes, decoded, consumed, stat)
    call check('entity wire decode ok', stat == EC_OK .and. consumed == size(bytes))
    call ent_of_cbor(decoded, dec, stat)
    call check('entity of_cbor recomputes hash', stat == EC_OK .and. dec%present)
    if (dec%present) call check('content_hash stable across round-trip', all(ent_hash(dec) == ent_hash(e)))
  end subroutine test_entity_roundtrip

  subroutine test_sign_verify()
    type(id_t) :: id
    type(entity_t) :: target, sig
    integer(int8) :: seed(32)
    seed = keystore_seed_of_hexbyte('11')
    id = id_of_seed(seed)
    call check('peer_id is base58', cap_is_peer_id(id%peer_id))
    target = ent_make('primitive/string', v_text('sign me'))
    sig = id_sign(id, target)
    call check('signature verifies against signer peer', id_verify_signature(sig, id%peer_entity))
    block
      type(id_t) :: other
      other = id_of_seed(keystore_seed_of_hexbyte('22'))
      call check('signature FAILS against wrong peer', .not. id_verify_signature(sig, other%peer_entity))
    end block
  end subroutine test_sign_verify

  subroutine test_capability_chain()
    type(id_t) :: a, b
    type(store_t) :: store
    type(entity_t) :: token, cap_sig, exec, exec_sig
    type(entity_t), allocatable :: inc(:)
    type(envelope_t) :: env
    type(ecf_value_t) :: tm, grants, absent
    integer :: verdict
    logical :: unresolvable
    absent%vkind = EV_ABSENT
    a = id_of_seed(keystore_seed_of_hexbyte('aa'))    ! responder / granter (local)
    b = id_of_seed(keystore_seed_of_hexbyte('bb'))    ! requester / grantee (author)
    store = store_new()
    call store_put_entity(store, a%peer_entity)
    call store_put_entity(store, b%peer_entity)
    ! A mints a token granting system/tree:get to B
    grants = v_arr_add(v_arr_empty(), cap_grant('system/tree', 'system/type/*', 'get', ''))
    tm = v_map_empty()
    tm = v_map_put(tm, 'granter', v_bytes(a%id_hash))
    tm = v_map_put(tm, 'grantee', v_bytes(b%id_hash))
    tm = v_map_put(tm, 'grants', grants)
    tm = v_map_put(tm, 'created_at', v_uint(cap_now_ms()))
    token = ent_make('system/capability/token', tm)
    cap_sig = id_sign(a, token)
    ! B authors an EXECUTE against A's system/tree
    exec = wire_make_execute('r1', '/' // a%peer_id // '/system/tree', 'get', &
                             wire_empty_params(), b%id_hash, ent_hash(token), absent)
    exec_sig = id_sign(b, exec)
    allocate(inc(5))
    inc(1) = token; inc(2) = a%peer_entity; inc(3) = b%peer_entity; inc(4) = cap_sig; inc(5) = exec_sig
    env = env_make(exec, inc)
    verdict = cap_verify_request(a%peer_id, store, env, unresolvable)
    call check('verify_request ALLOWs a valid delegated request', verdict == CV_ALLOW .and. .not. unresolvable)
    call check('permission check ALLOWs system/tree:get', &
      cap_check_permission(a%peer_id, a%peer_id, exec, token, '/' // a%peer_id // '/system/tree'))
    call check('chain-depth pre-check: single token is within bound', &
      .not. cap_chain_exceeds_depth(store, token, inc))
    ! tamper: swap in a signature over the wrong target -> AUTHN_FAIL
    block
      type(entity_t) :: bad_exec, bad_sig
      type(entity_t), allocatable :: inc2(:)
      type(envelope_t) :: env2
      integer :: v2
      logical :: u2
      bad_exec = wire_make_execute('r2', '/' // a%peer_id // '/system/tree', 'get', &
                                   wire_empty_params(), b%id_hash, ent_hash(token), absent)
      bad_sig = id_sign(a, bad_exec)     ! signed by A, but author claims B -> signer!=author
      allocate(inc2(5))
      inc2(1) = token; inc2(2) = a%peer_entity; inc2(3) = b%peer_entity; inc2(4) = cap_sig; inc2(5) = bad_sig
      env2 = env_make(bad_exec, inc2)
      v2 = cap_verify_request(a%peer_id, store, env2, u2)
      call check('verify_request DENIES a mis-signed request (401 authn)', v2 == CV_AUTHN_FAIL)
    end block
  end subroutine test_capability_chain

end program s3_selftest
