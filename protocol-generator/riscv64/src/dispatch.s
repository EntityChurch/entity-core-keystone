# dispatch.s — frame read loop + envelope parse + routing + handlers.
# GAS riscv64 (RV64GC). Entities/hashes via FFI; the envelope/data-map CBOR via cbor.s (A-ASM-004).
# Ported from asm-arm64/src/dispatch.s (the generic-syscall-table sibling). See macros.s for the
# aarch64→riscv64 convention (args a0-a5, ret a0, callee-saved s1-s10, CBOR writer cursor s6
# global; read_head multi-returns a1=major/a2=arg; get_text returns a0=bytes/a2=len; memeq len
# in a2). The register map is a clean bijection, so the inter-function ABI is preserved verbatim.

	.include "macros.s"
	.extern ec_content_hash
	.extern write_all, mcpy, strlen
	.extern read_head, skip_value, map_find, get_text, memeq
	.extern w_u8, w_map, w_arr, w_uint, w_txt, w_bstr, w_raw, w_cstr
	.extern ec_ed25519_verify, ec_ed25519_sign, ec_peerid_format
	.extern g_peerid, g_peerid_len, g_pubkey, g_seed, g_opengrants
	.section .rodata
k_root:   .asciz "root"
k_data:   .asciz "data"
k_op:     .asciz "operation"
k_rid:    .asciz "request_id"
k_result: .asciz "result"
k_status: .asciz "status"
k_nonce:  .asciz "nonce"
k_peerid: .asciz "peer_id"
k_ktypes: .asciz "key_types"
k_protos: .asciz "protocols"
k_ts:     .asciz "timestamp"
k_hfmts:  .asciz "hash_formats"
k_chash:  .asciz "content_hash"
k_type:   .asciz "type"
k_resource: .asciz "resource"
k_targets:  .asciz "targets"
k_params:   .asciz "params"
k_author:   .asciz "author"
k_capability: .asciz "capability"
k_uri:       .asciz "uri"
s_entity_scheme: .asciz "entity://"
ka_expires:  .asciz "expires_at"
ka_notbefore: .asciz "not_before"
s_star:     .asciz "*"
# F-peers (§5.4 is_peer_id): Base58 alphabet (Bitcoin), 58 bytes, no terminator needed —
# is_peer_id always scans exactly 58 entries. Ported from asm-arm64/src/dispatch.s.
s_base58_alpha: .ascii "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
v_hello:  .asciz "hello"
v_ed25519:.asciz "ed25519"
v_ed448:  .asciz "ed448"
v_ecore:  .asciz "entity-core/1.0"
v_ecfv1:  .asciz "ecfv1-sha256"
t_hello:  .asciz "system/protocol/connect/hello"
t_resp:   .asciz "system/protocol/execute/response"
t_put_result: .asciz "system/tree/put-result"
t_listing:    .asciz "system/tree/listing"
k_entity:     .asciz "entity"
k_expected:   .asciz "expected_hash"
k_path:       .asciz "path"
k_count:      .asciz "count"
k_offset:     .asciz "offset"
k_entries:    .asciz "entries"
k_hash:       .asciz "hash"
k_has_children: .asciz "has_children"
t_handler:    .asciz "system/handler"
t_deletion_marker: .asciz "system/deletion-marker"
t_iface:      .asciz "system/handler/interface"
t_reg_result: .asciz "system/handler/register-result"
k_manifest:   .asciz "manifest"
k_name:       .asciz "name"
k_pattern:    .asciz "pattern"
k_internal_scope: .asciz "internal_scope"
k_expr_path:  .asciz "expression_path"
k_interface:  .asciz "interface"
k_req_scope:  .asciz "requested_scope"
k_grant:      .asciz "grant"
p_hnd_slash:  .asciz "system/handler/"
p_cap_grants: .asciz "system/capability/grants/"
p_sig_slash:  .asciz "system/signature/"
p_sys_slash:  .asciz "system/"
p_sys_bare:   .asciz "system"
s_pat_connect: .asciz "system/protocol/connect"
s_iface_tree:  .asciz "system/handler/system/tree"
s_iface_connect: .asciz "system/handler/system/protocol/connect"
s_iface_cap:   .asciz "system/handler/system/capability"
s_pat_echo:    .asciz "system/validate/echo"
s_iface_echo:  .asciz "system/handler/system/validate/echo"
s_name_echo:   .asciz "validate/echo"
s_pat_dout:    .asciz "system/validate/dispatch-outbound"
s_iface_dout:  .asciz "system/handler/system/validate/dispatch-outbound"
s_name_dout:   .asciz "validate/dispatch-outbound"
va_dispatch:   .asciz "dispatch"
k_input_type:  .asciz "input_type"
k_output_type: .asciz "output_type"
v_prim_any:    .asciz "primitive/any"
p_cap_policy: .asciz "system/capability/policy/"
p_cap_revoke: .asciz "system/capability/revocations/"
t_revocation: .asciz "system/capability/revocation"
k_reason:     .asciz "reason"
k_revoked_at: .asciz "revoked_at"
k_peer_pattern: .asciz "peer_pattern"
ec_invalid_params: .asciz "invalid_params"
hexchars:     .ascii "0123456789abcdef"
ec_unexpected_params: .asciz "unexpected_params"
ec_hash_mismatch:     .asciz "hash_mismatch"
ec_invalid_path:      .asciz "invalid_path"
ec_unsupported_chf:   .asciz "unsupported_content_hash_format"

	.bss
	.lcomm b_req,    16777216
	.lcomm b_dhello, 4096
	.lcomm b_dresp,  8192
	.lcomm b_env,    16384
	.lcomm ch_hello, 64
	.lcomm ch_resp,  64
	# §6.3 put-admission scratch: the recomputed content_hash of the SUBMITTED entity.
	.lcomm ch_admit, 64
	.lcomm b_nonce,  32
	.lcomm b_ts,     16
	.lcomm b_hdr,    8
	.lcomm g_connfd, 8
	.lcomm g_rid_ptr,8
	.lcomm g_rid_len,8
	.lcomm g_dhlen,  8
	.lcomm g_drlen,  8
	.lcomm g_ms,     8
	.globl g_handler_ptr
	.globl g_handler_len
	.lcomm g_handler_ptr, 8
	.lcomm g_handler_len, 8
	# F-peers: extract_peer(execute.data.uri, local_peer_id) result — the target_peer used by
	# the §5.2 peers-scope check. Set by derive_handler; defaults to g_peerid/g_peerid_len.
	# .globl'd (like g_handler_ptr/len above) so tools/peers-scope-test.c can drive/inspect it.
	.globl g_target_peer_ptr
	.globl g_target_peer_len
	.lcomm g_target_peer_ptr, 8
	.lcomm g_target_peer_len, 8
	# ---- A-ASM-011 per-fork write store (path→entity) ----
	# store_idx: up to STORE_MAX entries × 32 B  [path_ptr, path_len, blob_ptr, blob_len].
	# store_arena: copy arena — the request buffer b_req is reused each frame, so a put must
	# COPY its path + entity bytes here to persist across frames of the connection. Sized for
	# a full --profile core sweep, which multiplexes every stateful probe (hundreds of puts,
	# incl. the concurrency sustained-load fan) onto ONE connection = ONE fork's store.
	.equ STORE_MAX,   8192
	.lcomm store_idx,   262144        # STORE_MAX × 32
	.lcomm store_count, 8
	.equ STORE_ARENA_CAP, 67108864    # 64 MiB
	.lcomm store_arena, 67108864
	.lcomm store_used,  8
	.lcomm b_prd_data,  256
	.lcomm prd_ch,      64
	.lcomm b_put_resp,  2048
	.lcomm put_resp_ch, 64
	.lcomm b_put_env,   4096
	.lcomm b_canon,     4096          # canonicalized store key: /{localPeerID}/{relative-path}
	# ---- listing scratch (trailing-slash get → system/tree/listing) ----
	# listing_ents: up to 384 distinct child segments × 32 B
	#   [0]=seg_ptr [8]=seg_len [16]=hash_ptr(0=null) [24]=has_children(0/1).
	.lcomm listing_ents, 12288
	.lcomm listing_n,   8
	.lcomm g_cpref_ptr, 8
	.lcomm g_cpref_len, 8
	.lcomm g_lprefix_ptr, 8
	.lcomm g_lprefix_len, 8
	.lcomm b_list_data, 2097152       # 2 MiB listing result data
	.lcomm list_data_ch, 64
	.lcomm b_list_env,  2097152
	# ---- system/handler register/unregister scratch ----
	.lcomm b_iface_data, 4096
	.lcomm iface_ch,     64
	.lcomm b_iface_ent,  4096
	.lcomm b_hdlr_data,  4096
	.lcomm hdlr_ch,      64
	.lcomm b_hdlr_ent,   4096
	.lcomm b_htok_data,  4096
	.lcomm g_htoklen,    8
	.lcomm htok_ch,      64
	.lcomm b_htok_ent,   4096
	.lcomm htok_sig,     64
	.lcomm b_hsig_data,  512
	.lcomm hsig_ch,      64
	.lcomm b_hsig_ent,   1024
	.lcomm b_regres_data, 4096
	.lcomm regres_ch,    64
	.lcomm b_regres_env, 8192
	.lcomm b_hpath,      1024
	.lcomm b_hex,        128
	.lcomm g_hpat_ptr,   8
	.lcomm g_hpat_len,   8
	.lcomm b_ent_scratch, 8192
	.lcomm g_chbuf,      8
	.lcomm g_tmplen,     8
	.lcomm b_ipath,      512
	.lcomm g_ipath_len,  8
	.lcomm b_zero33,     48
	# ---- multisig (§5.5) granter verification scratch ----
	.lcomm g_ms_thresh,  8
	.lcomm g_ms_valid,   8
	.lcomm g_ms_local,   8
	.lcomm g_ms_sigptr,  8
	.lcomm g_ms_sigs,    256          # up to 32 signer-hash pointers
	# ---- §5.5 delegation-chain walk + §5.5a canonicalization frames ----
	# A frame is a granter's peer_id (base58, <=128 bytes), derived from its system/peer
	# entity in `included` — it is not on the wire. `c` = the link nearer the leaf, `p` =
	# the link nearer the root; `s`/`q` are the sub/super sides of whichever comparison is
	# running, so the exclude direction can be reversed without copying a frame.
	.lcomm g_cfr,      128
	.lcomm g_cfrlen,   8
	.lcomm g_pfr,      128
	.lcomm g_pfrlen,   8
	.lcomm g_sfr_ptr,  8
	.lcomm g_sfr_len,  8
	.lcomm g_qfr_ptr,  8
	.lcomm g_qfr_len,  8
	.lcomm g_dfr,      128            # dispatch-surface frame (the presented cap's granter)
	.lcomm g_dfrlen,   8
	.lcomm b_canon_a,  1024           # canonicalized child / request-target
	.lcomm b_canon_b,  1024           # canonicalized parent / grant pattern
	.lcomm g_pgee,     48             # child link's granter hash, carried across one hop
	.lcomm g_now,      8              # §5.5 `t` — sampled ONCE per verdict, never per link
	.lcomm g_link_ch,  64             # recomputed content hash of the link under test
	# ---- §6.2 CAP-5 / §5.6 MIN_DEFINED mint ceiling ----
	.lcomm g_caller_td,  8            # the caller capability's token data (the bounding term)
	.lcomm g_params_data, 8           # request params.data (carries ttl_ms)
	.lcomm g_exp_have,   8
	.lcomm g_expv,       8
	# ---- revoke scratch ----
	.lcomm b_revoke_data, 512
	.lcomm revoke_ch,    64
	.lcomm b_revoke_ent, 1024



	.text
	.globl peer_bootstrap
	.type peer_bootstrap, @function
# Compute this peer's identity_hash = content_hash of its system/peer entity, and
# cache the peer-entity data bytes (reused when this peer is emitted in `included`).
peer_bootstrap:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s6, 16(sp)                 # preserve the global cursor across this build
	lla  s6, b_peerdata            # s6 = writer cursor
	li   a1, 2
	call w_map
	lla  a0, ka_ktype
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_pubkey
	call w_cstr
	lla  a1, g_pubkey
	li   a2, 32
	call w_bstr
	lla  t0, b_peerdata
	sub  a2, s6, t0                 # peerdata_len = cursor - b_peerdata
	lla  t0, g_peerdata_len
	sd   a2, 0(t0)
	lla  a0, ta_peer
	li   a1, 11
	lla  a2, b_peerdata
	lla  t0, g_peerdata_len
	ld   a3, 0(t0)
	lla  a4, g_identity_hash
	call ec_content_hash
	ld   s6, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# =====================================================================
# conn_serve(a0 = connfd) — read framed requests, dispatch each, until EOF.
# =====================================================================
	.globl conn_serve
	.type conn_serve, @function
# s1 = connfd (callee-saved), s2 = frame/remaining length across drain.
conn_serve:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	mv   s0, sp
	mv   s1, a0                     # connfd
	lla  t0, g_connfd
	sd   s1, 0(t0)
	# Per-connection handshake state. The fork-per-connection path gets a fresh zeroed
	# .bss for free, but host.s's fork-exhaustion fallback serves a connection INLINE in
	# the parent and reuses one process across connections — so the reset belongs at the
	# start of a CONNECTION. It matters now that §4.7 rows 8/9 read the latch: a second
	# hello must see what its predecessor left, and only a new connection may clear it.
	lla  t0, g_authenticated
	sd   zero, 0(t0)
	lla  t0, g_hello_done
	sd   zero, 0(t0)
	lla  t0, g_hello_peer_len
	sd   zero, 0(t0)
	call seed_dispatch_entities     # publish §6.2 native dispatch entities into this fork
.Lcs_loop:
	# read 4-byte BE length header
	mv   a0, s1
	lla  a1, b_hdr
	li   a2, 4
	call read_full
	li   t0, 4
	bne  a0, t0, .Lcs_done
	lla  t0, b_hdr
	lwu  t0, 0(t0)
	bswap32 t0, t0                  # BE → host
	beqz t0, .Lcs_loop              # zero-length frame: ignore
	li   t1, 0x1000000             # 0x1000000: > 16 MiB (§9.1 default payload cap) → 413, keep serving
	bgtu t0, t1, .Lcs_oversize
	# read body
	mv   a0, s1
	lla  a1, b_req
	mv   a2, t0                     # frame len (zero-extended)
	mv   s2, a2
	call read_full
	bne  a0, s2, .Lcs_done
	call dispatch
	j    .Lcs_loop
.Lcs_oversize:
	# §4.10(a): answer 413 payload_too_large NOW, then close. request_id is unknown
	# (the body was never parsed) → echo empty, which the section's emission shape
	# explicitly provides for: "SHOULD emit a 413 correlated by request_id when the
	# id is available, and otherwise MAY close the connection after a best-effort
	# coded frame".
	#
	# This used to DRAIN the whole declared body first — in <=1 MiB chunks, up to the
	# 4 GiB a 32-bit length header can name — so the connection could stay framed and
	# keep serving. That reads as the more conformant choice and is the opposite:
	# §4.10(a) requires rejecting "BEFORE fully buffering or decoding it where the
	# transport allows", and the drain is the fully-buffering it forbids, done one
	# buffer at a time. A sender that declares 4 GiB and sends 1 KiB parks the child
	# in read(2) for as long as it likes, and no 413 is ever emitted because the peer
	# is still politely waiting for the payload it already knows it will refuse.
	# Measured on x86-64 2026-08-29: the oracle timed out reading the response every
	# time and recorded "connection terminated without a 413 frame".
	#
	# Staying framed is worth nothing once the frame is known to be unservable, and
	# the connection is the attacker's to waste, not ours.
	lla  t0, g_rid_len
	sd   zero, 0(t0)
	li   a0, 413
	lla  a1, ec_payload_too_large
	call send_error
	j    .Lcs_done
.Lcs_done:
	mv   a0, s1
	ksys SYS_close
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# read_full(a0=fd, a1=buf, a2=n) -> a0 = bytes read (n on success)
	.type read_full, @function
# s1=fd, s2=buf, s3=remaining, s4=got.
read_full:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s1, a0                     # fd
	mv   s2, a1                     # buf
	mv   s3, a2                     # remaining
	li   s4, 0                      # got
.Lrf:
	beqz s3, .Lrf_done
	mv   a0, s1
	add  a1, s2, s4
	mv   a2, s3
	ksys SYS_read
	blez a0, .Lrf_done             # EOF/error
	add  s4, s4, a0
	sub  s3, s3, a0
	j    .Lrf
.Lrf_done:
	mv   a0, s4
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# =====================================================================
# dispatch — parse b_req envelope, route by operation. (only hello for now)
# =====================================================================
	.type dispatch, @function
# s1 = exec data map. op ptr/len (x86 held them in volatile r8/r9 across memeq,
# which preserves r8/r9; memeq clobbers t0/t1, so promote to callee-saved
# s2 = op ptr, s3 = op len).
dispatch:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	# root = map_find(b_req, "root")
	lla  a0, b_req
	lla  a1, k_root
	li   a2, 4
	call map_find
	beqz a0, .Ld_ret
	lla  t0, g_root_ptr
	sd   a0, 0(t0)
	# §7a: a root of type system/protocol/execute/response is a reply to one of our outbound
	# reentry echoes — demux it to its pending dispatch-outbound instead of dispatching.
	# a0 already = root ptr
	lla  a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Ld_notresp
	call get_text
	li   t0, 32
	bne  a2, t0, .Ld_notresp
	mv   a1, a0
	lla  a0, t_resp
	li   a2, 32                     # memeq len in a2
	call memeq
	beqz a0, .Ld_notresp
	lla  t0, g_root_ptr
	ld   a0, 0(t0)
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Ld_ret
	call handle_dispatch_response
	j    .Ld_ret
.Ld_notresp:
	# exec = map_find(root, "data")
	lla  t0, g_root_ptr
	ld   a0, 0(t0)
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Ld_ret
	mv   s1, a0                     # s1 = exec data map
	# request_id → save
	mv   a0, s1
	lla  a1, k_rid
	li   a2, 10
	call map_find
	beqz a0, .Ld_ret
	call get_text                   # a0=ptr, a2=len
	lla  t0, g_rid_ptr
	sd   a0, 0(t0)
	lla  t0, g_rid_len
	sd   a2, 0(t0)
	# §1.4 / §6.5 step 3 — the ADDRESS gate, before the op ladder (which is where this peer
	# resolves a handler at all) and therefore before any capability question is asked. Sited
	# after the request_id is saved so the 400 can carry it. See uri_targets_local.
	mv   a0, s1                     # exec data map
	call uri_targets_local
	bnez a0, .Ld_ret                # foreign address → 400 invalid_request already sent
	# operation
	mv   a0, s1
	lla  a1, k_op
	li   a2, 9
	call map_find
	beqz a0, .Ld_ret
	call get_text                   # a0=opptr, a2=oplen
	# route: save op (ptr in a0, len in a2) then compare
	mv   s2, a0                     # op ptr
	mv   s3, a2                     # op len
	# Every branch below dispatches on LENGTH first and only then compares bytes, so a
	# length collision with an op we do route is the case to get right: a byte mismatch
	# must fall through to .Ld_unknown (→ 501 unsupported_operation), never to .Ld_ret.
	# Falling to .Ld_ret answers NOTHING, and §4.9(c) deliver-or-signal makes that the
	# one outcome a peer may not produce — the caller cannot tell it from a dead peer and
	# waits out its own timeout. Measured 2026-08-30 on asm-x86_64: `ping` collides with
	# `echo` at length 4 and was dropped on exactly this branch. It costs the caller a
	# full 20 s read deadline EVERY connection, which is why t2_2_connection_churn
	# consumed the entire 10-minute budget across 29 of its 100 cycles and starved nine
	# categories — a §4.9(c) violation presenting as a connection-pressure failure.
	# op == "hello"?
	li   t0, 5
	bne  s3, t0, .Ld_try_auth
	mv   a1, s2
	lla  a0, v_hello
	li   a2, 5
	call memeq
	beqz a0, .Ld_unknown             # len 5 but not "hello" → 501, never a silent drop
	# §4.5 negotiation: reject a hello whose advertised hash_formats/key_types/protocols
	# are disjoint from ours (400) before building the happy-path response.
	mv   a0, s1                     # exec data map
	call check_hello_negotiation
	bnez a0, .Ld_ret               # rejected (400 already sent)
	# §4.7 rows 8/9 — a SECOND hello. Two rows, two codes, one status:
	#   established -> 409 connection_already_established
	#   half-open   -> 409 connection_sequence_error  (§4.7's own worked example: "a second
	#                  hello after hello_done" is an operation this peer implements arriving
	#                  in a state that forbids it)
	#
	# CONTENT BEFORE STATE, DELIBERATELY. §4.5 and §4.7 fix no precedence between the
	# negotiation refusals and these, and the order is OBSERVABLE: measured on `prolog`,
	# negotiation/format_disjoint_reject's disjoint hello arrives on a HALF-OPEN connection
	# in a full core run and on a FRESH one when the category is driven alone, so a
	# state-first ladder answers 409 there and passes in isolation. Content-first satisfies
	# both vectors, which is why it is the order here.
	lla  t0, g_authenticated
	ld   t0, 0(t0)
	bnez t0, .Ld_hello_established
	lla  t0, g_hello_done
	ld   t0, 0(t0)
	bnez t0, .Ld_hello_midhandshake
	mv   a0, s1                     # exec data map
	call record_hello_peer          # latches hello_done + the greeted peer_id (row 8)
	call build_hello_response
	j    .Ld_ret
.Ld_hello_established:
	li   a0, 409
	lla  a1, ec_conn_already
	call send_error
	j    .Ld_ret
.Ld_hello_midhandshake:
	li   a0, 409
	lla  a1, ec_conn_seq
	call send_error
	j    .Ld_ret
.Ld_try_auth:
	# op == "authenticate"?
	li   t0, 12
	bne  s3, t0, .Ld_try_echo
	mv   a1, s2
	lla  a0, va_authenticate
	li   a2, 12
	call memeq
	beqz a0, .Ld_unknown             # len 12 but not "authenticate" → 501
	mv   a0, s1                     # exec data map ptr
	call build_authenticate_response
	j    .Ld_ret
.Ld_try_echo:
	# op == "echo"? (system/validate/echo)
	li   t0, 4
	bne  s3, t0, .Ld_try_get
	mv   a1, s2
	lla  a0, va_echo
	li   a2, 4
	call memeq
	beqz a0, .Ld_unknown             # len 4 but not "echo" — e.g. "ping" — → 501
	mv   a0, s1
	call build_echo_response
	j    .Ld_ret
.Ld_try_get:
	# op == "get"? (system/tree get) — resolve against the store + embedded read-only store.
	li   t0, 3
	bne  s3, t0, .Ld_try_request
	mv   a1, s2
	lla  a0, va_get
	li   a2, 3
	call memeq
	beqz a0, .Ld_try_put           # len 3 but not "get" → maybe "put"
	mv   a0, s1                     # exec data map ptr
	call serve_tree_get
	j    .Ld_ret
.Ld_try_put:
	# op == "put"? (system/tree put) — write into the per-fork store (A-ASM-011).
	li   t0, 3
	bne  s3, t0, .Ld_try_request
	mv   a1, s2
	lla  a0, va_put
	li   a2, 3
	call memeq
	beqz a0, .Ld_try_request
	mv   a0, s1                     # exec data map ptr
	call serve_tree_put
	j    .Ld_ret
.Ld_try_request:
	# op == "request"? (system/capability request) — mint a token per params.data.grants.
	li   t0, 7
	bne  s3, t0, .Ld_try_register
	mv   a1, s2
	lla  a0, va_request
	li   a2, 7
	call memeq
	beqz a0, .Ld_try_register
	mv   a0, s1                     # exec data map ptr
	call build_request_response
	j    .Ld_ret
.Ld_try_register:
	# op == "register"? (system/handler register) — write handler entities to the store.
	li   t0, 8
	bne  s3, t0, .Ld_try_unregister
	mv   a1, s2
	lla  a0, va_register
	li   a2, 8
	call memeq
	beqz a0, .Ld_try_delegate
	mv   a0, s1
	call serve_register
	j    .Ld_ret
.Ld_try_delegate:
	# op == "delegate"? (system/capability delegate) — same-peer-only; unsupported in v1.
	mv   a1, s2
	lla  a0, va_delegate
	li   a2, 8
	call memeq
	beqz a0, .Ld_try_dispatch
	mv   a0, s1
	call serve_delegate
	j    .Ld_ret
.Ld_try_dispatch:
	# op == "dispatch"? (§7a system/validate/dispatch-outbound) — originate a reentry echo.
	mv   a1, s2
	lla  a0, va_dispatch
	li   a2, 8
	call memeq
	beqz a0, .Ld_unknown
	mv   a0, s1
	call serve_dispatch_outbound
	j    .Ld_ret
.Ld_try_unregister:
	# op == "unregister"? (system/handler unregister) — remove handler entities.
	li   t0, 10
	bne  s3, t0, .Ld_try_configure
	mv   a1, s2
	lla  a0, va_unregister
	li   a2, 10
	call memeq
	beqz a0, .Ld_unknown
	mv   a0, s1
	call serve_unregister
	j    .Ld_ret
.Ld_try_configure:
	# op == "configure"? (system/capability configure) — write a peer policy-entry.
	li   t0, 9
	bne  s3, t0, .Ld_try_revoke
	mv   a1, s2
	lla  a0, va_configure
	li   a2, 9
	call memeq
	beqz a0, .Ld_unknown
	mv   a0, s1
	call serve_configure
	j    .Ld_ret
.Ld_try_revoke:
	# op == "revoke"? (system/capability revoke) — write a revocation marker.
	li   t0, 6
	bne  s3, t0, .Ld_unknown
	mv   a1, s2
	lla  a0, va_revoke
	li   a2, 6
	call memeq
	beqz a0, .Ld_unknown
	mv   a0, s1
	call serve_revoke
	j    .Ld_ret
.Ld_unknown:
	# §4.7's LAST row FIRST: an operation name the responder does not implement, in ANY
	# state, is 400 invalid_request — but ONLY on the CONNECT handler. The same unknown
	# operation on system/tree is 501 unsupported_operation (§3.3's 501 slot) and on an
	# unregistered path 404 handler_not_found, so the scoping is what keeps three different
	# rows apart. Without it this peer answered 501 for an unknown connect op, which points
	# the caller at a capability it might obtain when the defect is the operation NAME.
	mv   a0, s1                     # exec data map
	call uri_is_connect
	beqz a0, .Ld_unknown_notconnect
	li   a0, 400
	lla  a1, ec_invalid_request
	call send_error
	j    .Ld_ret
.Ld_unknown_notconnect:
	# An operation this peer doesn't route falls into two classes:
	#  - a KNOWN vocabulary op (delegate/configure/revoke/register/unregister/put) we don't
	#    (yet) implement gets an authorization decision — if the presented capability doesn't
	#    cover it, that's a 403 denial (verify_get_scope); otherwise it falls through to 501.
	#  - a genuinely UNKNOWN op → 501 unsupported_operation up front.
	# (A silent no-reply would block validate-peer ~20s/probe, so we always answer.)
	mv   a0, s2                     # op ptr
	mv   a1, s3                     # op len
	call op_is_known
	beqz a0, .Ld_501               # unknown op → 501
	mv   a0, s1                     # exec data map
	call verify_get_scope
	bnez a0, .Ld_ret               # 403 already sent
.Ld_501:
	li   a0, 501
	lla  a1, ec_unsupported_op
	call send_error
.Ld_ret:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# op_is_known(a0 = op ptr, a1 = op len) -> a0 = 1 if op is a known capability/handler/tree
# write op we recognise but don't route to a dedicated handler (delegate/configure/revoke/
# register/unregister/put). Such ops get an authorization decision (403); anything else is
# a genuinely unknown operation (501 unsupported_operation).
	.type op_is_known, @function
# s1 = op ptr, s2 = op len (survive memeq).
op_is_known:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	mv   s0, sp
	mv   s1, a0                     # op ptr
	mv   s2, a1                     # op len
	li   t0, 8
	bne  s2, t0, .Loik_c9
	mv   a0, s1
	lla  a1, va_delegate
	li   a2, 8
	call memeq
	bnez a0, .Loik_yes
	mv   a0, s1
	lla  a1, va_register
	li   a2, 8
	call memeq
	bnez a0, .Loik_yes
	j    .Loik_no
.Loik_c9:
	li   t0, 9
	bne  s2, t0, .Loik_c6
	mv   a0, s1
	lla  a1, va_configure
	li   a2, 9
	call memeq
	bnez a0, .Loik_yes
	j    .Loik_no
.Loik_c6:
	li   t0, 6
	bne  s2, t0, .Loik_c10
	mv   a0, s1
	lla  a1, va_revoke
	li   a2, 6
	call memeq
	bnez a0, .Loik_yes
	j    .Loik_no
.Loik_c10:
	li   t0, 10
	bne  s2, t0, .Loik_c3
	mv   a0, s1
	lla  a1, va_unregister
	li   a2, 10
	call memeq
	bnez a0, .Loik_yes
	j    .Loik_no
.Loik_c3:
	li   t0, 3
	bne  s2, t0, .Loik_no
	mv   a0, s1
	lla  a1, va_put
	li   a2, 3
	call memeq
	bnez a0, .Loik_yes
.Loik_no:
	li   a0, 0
	j    .Loik_ret
.Loik_yes:
	li   a0, 1
.Loik_ret:
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# =====================================================================
# build_hello_response — construct + send a valid hello EXECUTE_RESPONSE.
# =====================================================================
	.type build_hello_response, @function
# s6 = writer cursor (global). s1 = env len across the two write_all calls.
build_hello_response:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s6, 24(sp)
	mv   s0, sp
	# nonce (32 CSPRNG bytes)
	lla  a0, b_nonce
	li   a1, 32
	li   a2, 0
	ksys SYS_getrandom
	# timestamp ms = sec*1000 + nsec/1e6
	li   a0, 0                      # CLOCK_REALTIME
	lla  a1, b_ts
	ksys SYS_clock_gettime
	lla  t0, b_ts
	ld   t1, 0(t0)                  # sec
	li   t2, 1000
	mul  t1, t1, t2                 # sec*1000
	lla  t0, b_ts
	ld   t3, 8(t0)                  # nsec
	li   t4, 1000000               # 1000000 = 0x0F4240
	divu t3, t3, t4                 # nsec/1e6
	add  t1, t1, t3
	lla  t0, g_ms
	sd   t1, 0(t0)

	# ---- D_hello (a6) into b_dhello ----
	lla  s6, b_dhello
	li   a1, 6
	call w_map
	lla  a0, k_nonce
	call w_cstr
	lla  a1, b_nonce
	li   a2, 32
	call w_bstr
	lla  a0, k_peerid
	call w_cstr
	lla  a1, g_peerid
	lla  t0, g_peerid_len
	ld   a2, 0(t0)
	call w_txt
	lla  a0, k_ktypes
	call w_cstr
	li   a1, 2
	call w_arr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, v_ed448
	call w_cstr
	lla  a0, k_protos
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, v_ecore
	call w_cstr
	lla  a0, k_ts
	call w_cstr
	lla  t0, g_ms
	ld   a1, 0(t0)
	call w_uint
	lla  a0, k_hfmts
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, v_ecfv1
	call w_cstr
	# dhello_len = s6 - b_dhello
	lla  t0, b_dhello
	sub  a2, s6, t0
	lla  t0, g_dhlen
	sd   a2, 0(t0)
	# ch_hello = ec_content_hash("system/protocol/connect/hello"(29), D_hello)
	lla  a0, t_hello
	li   a1, 29
	lla  a2, b_dhello
	lla  t0, g_dhlen
	ld   a3, 0(t0)
	lla  a4, ch_hello
	call ec_content_hash

	# ---- D_resp (a3) into b_dresp ----
	lla  s6, b_dresp
	li   a1, 3
	call w_map
	lla  a0, k_result               # "result" → hello entity
	call w_cstr
	li   a1, 3
	call w_map
	lla  a0, k_data
	call w_cstr
	lla  a1, b_dhello               # embed D_hello verbatim
	lla  t0, g_dhlen
	ld   a2, 0(t0)
	call w_raw
	lla  a0, k_type
	call w_cstr
	lla  a0, t_hello
	call w_cstr
	lla  a0, k_chash
	call w_cstr
	lla  a1, ch_hello
	li   a2, 33
	call w_bstr
	lla  a0, k_status               # "status" → 200
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid                  # "request_id" → echo
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	# dresp_len
	lla  t0, b_dresp
	sub  a2, s6, t0
	lla  t0, g_drlen
	sd   a2, 0(t0)
	# ch_resp = ec_content_hash("system/protocol/execute/response"(32), D_resp)
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_dresp
	lla  t0, g_drlen
	ld   a3, 0(t0)
	lla  a4, ch_resp
	call ec_content_hash

	# ---- envelope (a1) into b_env ----
	lla  s6, b_env
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	li   a1, 3
	call w_map
	lla  a0, k_data
	call w_cstr
	lla  a1, b_dresp                # embed D_resp verbatim
	lla  t0, g_drlen
	ld   a2, 0(t0)
	call w_raw
	lla  a0, k_type
	call w_cstr
	lla  a0, t_resp
	call w_cstr
	lla  a0, k_chash
	call w_cstr
	lla  a1, ch_resp
	li   a2, 33
	call w_bstr
	# env_len
	lla  t0, b_env
	sub  s1, s6, t0                 # s1 = env len
	# frame header: 4-byte BE len
	bswap32 t0, s1
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_env
	mv   a2, s1
	call write_all
	ld   s6, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret
	.section .rodata
ka_ktype:  .asciz "key_type"
ka_pubkey: .asciz "public_key"
ta_peer:   .asciz "system/peer"
ta_token:  .asciz "system/capability/token"
ta_sig:    .asciz "system/signature"
ta_grant:  .asciz "system/capability/grant"
t_prim_any: .asciz "primitive/any"
t_execute: .asciz "system/protocol/execute"
k_value:   .asciz "value"
k_target:  .asciz "target"
k_reentry_capability: .asciz "reentry_capability"
k_reentry_granter: .asciz "reentry_granter"
k_reentry_cap_signature: .asciz "reentry_cap_signature"
va_authenticate: .asciz "authenticate"
ka_params: .asciz "params"
ka_included: .asciz "included"
ka_granter: .asciz "granter"
ka_grantee: .asciz "grantee"
ka_grants: .asciz "grants"
ka_created: .asciz "created_at"
ka_token:  .asciz "token"
ka_signer: .asciz "signer"
ka_target: .asciz "target"
ka_algo:   .asciz "algorithm"
ka_sig:    .asciz "signature"
ka_handlers: .asciz "handlers"
ka_resources: .asciz "resources"
ka_operations: .asciz "operations"
ka_peers:  .asciz "peers"
ka_include: .asciz "include"
va_star:   .asciz "*"
va_star2:  .asciz "/*/*"
va_systree: .asciz "system/tree"
va_systype_g: .asciz "system/type/*"
va_syshandler_g: .asciz "system/handler/*"
va_get:    .asciz "get"
va_syscap: .asciz "system/capability"
va_request: .asciz "request"
va_delegate: .asciz "delegate"
va_configure: .asciz "configure"
va_revoke:   .asciz "revoke"
va_register: .asciz "register"
va_unregister: .asciz "unregister"
va_put:      .asciz "put"
ta_auth:   .asciz "system/protocol/connect/authenticate"
t_error:   .asciz "system/protocol/error"
k_code:    .asciz "code"
va_echo:   .asciz "echo"
ec_invalid_nonce: .asciz "invalid_nonce"
ec_identity_mismatch: .asciz "identity_mismatch"
ec_auth_failed: .asciz "authentication_failed"
ec_not_found: .asciz "not_found"
ec_payload_too_large: .asciz "payload_too_large"
ec_not_impl:  .asciz "not_implemented"
ec_unsupported_op: .asciz "unsupported_operation"
ec_incompat_hf: .asciz "incompatible_hash_format"
ec_unsup_kt:  .asciz "unsupported_key_type"
ec_cap_denied: .asciz "capability_denied"
ec_forbidden_pattern: .asciz "forbidden_pattern"
ec_unresolvable_grantee: .asciz "unresolvable_grantee"
ec_chain_depth: .asciz "chain_depth_exceeded"
ec_invalid_request: .asciz "invalid_request"
# ---- §4.7 connect-error table (0.8.2.4): three codes this peer did not carry ----
# A STATE CONFLICT IS 409 AND AN UNKNOWN OPERATION IS 400, and the two 409s are two
# ROWS: "connection already established" is its own row, while a second hello BEFORE
# authenticate is the out-of-order row -- §4.7's own worked example. The table is a
# normative MUST-emit contract because clients key error handling off result.data.code,
# so a peer that collapses these into one code selects the wrong remedy for the caller.
ec_incompat_proto: .asciz "incompatible_protocol"
ec_conn_seq:  .asciz "connection_sequence_error"
ec_conn_already: .asciz "connection_already_established"
va_sysconnect: .asciz "system/protocol/connect"
ka_parent:   .asciz "parent"
ka_threshold: .asciz "threshold"
ka_signers:  .asciz "signers"
# ---- §5.5 delegation-chain / §5.6 attenuation vocabulary ----
ka_exclude:  .asciz "exclude"
ka_constraints: .asciz "constraints"
ka_allowances: .asciz "allowances"
ka_deleg_caveats: .asciz "delegation_caveats"
ka_no_delegation: .asciz "no_delegation"
ka_max_deleg_depth: .asciz "max_delegation_depth"
ka_max_deleg_ttl: .asciz "max_delegation_ttl"
ka_ttl_ms:   .asciz "ttl_ms"

	.bss
	# Sized for the full 16 MiB entity cap: a get now serves store-written entities of
	# arbitrary size (the concurrency `slow` binding is deliberately large), whose bytes are
	# copied verbatim into the response — a 2 KiB buffer overflowed into neighbouring .bss.
	.lcomm b_get_data,   17825792     # 17 MiB (16 MiB entity + envelope headroom)
	.lcomm get_data_ch,  64
	.lcomm b_get_env,    17825792
	.lcomm b_incl_tab,   512
	.lcomm tok_recompute_ch, 64
	.lcomm b_derived_pid, 128
	.lcomm g_derived_pid_len, 8
	.lcomm g_auth_hash,  64
	# RT-6 (§4.6): set once build_authenticate_response accepts a valid authenticate on this
	# connection (fork-per-connection, so this .bss word is per-connection state); a second
	# authenticate frame on the same connfd is rejected before any nonce/signature work.
	.lcomm g_authenticated, 8
	# §4.7 rows 8/9, same per-connection .bss reasoning as the latch above.
	.lcomm g_hello_done, 8            # 0/1, set only on the ACCEPT path — a REFUSED hello
                                           # must leave the connection fresh so the caller may
                                           # retry with a conformant one.
	.lcomm b_hello_peer, 128          # §4.7 row 8's second input: the peer_id this connection
	.lcomm g_hello_peer_len, 8        # was greeted BY, for the authenticate-side comparison.
	.lcomm b_err,        128
	.lcomm err_ch,       64
	.lcomm b_er_resp,    2048
	.lcomm er_resp_ch,   64
	.lcomm b_er_env,     4096
	.lcomm b_peerdata,   256
	.lcomm g_peerdata_len, 8
	.lcomm g_identity_hash, 64
	.lcomm g_client_pubkey, 64
	.lcomm g_grantee,    64
	.lcomm g_pid_kt,     8
	.lcomm g_pid_ht,     8
	.lcomm g_pid_dlen,   8
	.lcomm b_pid_digest, 64
	.lcomm g_reqg_ptr,   8
	.lcomm g_reqg_len,   8
	.lcomm b_clientpeer, 128
	.lcomm b_tokdata,    2048
	.lcomm g_toklen,     8
	.lcomm tok_ch,       64
	.lcomm tok_sig,      64
	.lcomm b_sigdata,    512
	.lcomm g_sigdlen,    8
	.lcomm sig_ch,       64
	.lcomm b_grantdata,  128
	.lcomm g_grlen,      8
	.lcomm grant_ch,     64
	.lcomm b_ar_resp,    4096
	.lcomm g_ardlen,     8
	.lcomm resp_ch2,     64
	.lcomm b_ar_env,     32768
	.lcomm g_created,    8
	# ---- §7a dispatch-outbound reentry (bidirectional dispatch + demux) ----
	# pending_tab: 16 entries × 80 B  [0]=echo_rid(32) [32]=erid_len [40]=disp_rid(32) [72]=drid_len
	.lcomm pending_tab,  1280
	.lcomm pending_n,    8
	.lcomm echo_ctr,     8
	.lcomm b_erid,       32
	.lcomm g_erid_len,   8
	.lcomm b_eparams,    2048
	.lcomm eparams_ch,   64
	.lcomm b_edata,      4096
	.lcomm edata_ch,     64
	.lcomm esig_bytes,   64
	.lcomm b_esig,       512
	.lcomm esig_ch,      64
	.lcomm do_incl_tab,  512
	.lcomm g_rcap_hash,  8
	.lcomm b_do_inner,   2048
	.lcomm do_inner_ch,  64
	.lcomm b_do_data,    4096
	.lcomm do_data_ch,   64
	.lcomm b_do_env,     8192
	.lcomm g_root_ptr,   8
	.lcomm g_dtarget_ptr, 8
	.lcomm g_dtarget_len, 8
	.lcomm g_eplen,      8
	.lcomm g_edlen,      8
	.lcomm g_dvalue_ptr, 8
	.lcomm g_dvalue_len, 8



	.text
# w_entity(a0=type_cstr, a1=data_ptr, a2=data_len, a3=chash_ptr) — emit an
# entity map {data:<raw>, type:<cstr>, content_hash:<33>}. Uses s6 cursor.
	.type w_entity, @function
w_entity:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s1, a0                     # type cstr
	mv   s2, a1                     # data ptr
	mv   s3, a2                     # data len
	mv   s4, a3                     # chash ptr
	li   a1, 3
	call w_map
	lla  a0, k_data
	call w_cstr
	mv   a1, s2                     # data ptr
	mv   a2, s3                     # data len
	call w_raw
	lla  a0, k_type
	call w_cstr
	mv   a0, s1                     # type cstr
	call w_cstr
	lla  a0, k_chash
	call w_cstr
	mv   a1, s4                     # chash ptr
	li   a2, 33
	call w_bstr
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# now_ms() -> a0 = wall-clock ms
	.type now_ms, @function
now_ms:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	li   a0, 0                      # CLOCK_REALTIME
	lla  a1, b_ts
	ksys SYS_clock_gettime
	lla  t0, b_ts
	ld   t1, 0(t0)                  # tv_sec
	li   t2, 1000
	mul  t1, t1, t2                 # sec * 1000
	ld   t3, 8(t0)                  # tv_nsec
	li   t4, 1000000               # 1000000 = 0xF4240
	divu t3, t3, t4                 # nsec / 1000000
	add  a0, t1, t3
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# emit_grants — emit the grants ARRAY (cursor s6) per g_opengrants.
	.type emit_grants, @function
emit_grants:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	lla  t0, g_opengrants
	ld   t0, 0(t0)
	beqz t0, .Leg_floor
	li   a1, 1
	call w_arr
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	tail emit_grant_wild
.Leg_floor:
	li   a1, 2
	call w_arr
	call emit_grant_floor1
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	tail emit_grant_floor2

# {peers:[*], handlers:[*], resources:[*,/*/*], operations:[*]}
	.type emit_grant_wild, @function
emit_grant_wild:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	li   a1, 4
	call w_map
	lla  a0, ka_peers
	call w_incl1
	lla  a0, ka_handlers
	call w_incl1
	lla  a0, ka_resources
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 2
	call w_arr
	lla  a0, va_star
	call w_cstr
	lla  a0, va_star2
	call w_cstr
	lla  a0, ka_operations
	call w_incl1
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# w_incl1(a0=field_cstr) — emit  <field>: {include:["*"]}
	.type w_incl1, @function
w_incl1:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, va_star
	call w_cstr
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# floor grant 1: {handlers:{include:[system/tree]}, resources:{include:[system/type/*,
#   system/handler/*]}, operations:{include:[get]}}
	.type emit_grant_floor1, @function
emit_grant_floor1:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	li   a1, 3
	call w_map
	lla  a0, ka_handlers
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, va_systree
	call w_cstr
	lla  a0, ka_resources
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 2
	call w_arr
	lla  a0, va_systype_g
	call w_cstr
	lla  a0, va_syshandler_g
	call w_cstr
	lla  a0, ka_operations
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, va_get
	call w_cstr
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# floor grant 2: {handlers:{include:[system/capability]}, resources:{include:[]},
#   operations:{include:[request]}}
	.type emit_grant_floor2, @function
emit_grant_floor2:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	li   a1, 3
	call w_map
	lla  a0, ka_handlers
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, va_syscap
	call w_cstr
	lla  a0, ka_resources
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 0
	call w_arr
	lla  a0, ka_operations
	call w_cstr
	li   a1, 1
	call w_map
	lla  a0, ka_include
	call w_cstr
	li   a1, 1
	call w_arr
	lla  a0, va_request
	call w_cstr
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret
# build_authenticate_response(a0 = exec data map ptr)
	.type build_authenticate_response, @function
# Callee-saved held across the build:
#   s3 = exec data map (was r12), s4 = params entity / later sig data map (was r13),
#   s5 = pdata (was r14), s6 = CBOR cursor (was r15, global), s1 = sig ptr temp (was rbx).
build_authenticate_response:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)
	mv   s0, sp
	mv   s3, a0                     # exec data map
	# RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established connection must
	# not be re-processed (it would re-verify the same still-cached nonce and re-issue a
	# grant). The nonce is documented single-use — reject outright, before any nonce/signature
	# or even frame-shape work.
	lla  t0, g_authenticated
	ld   t0, 0(t0)
	beqz t0, .Lauth_replay_ok
	li   a0, 401
	lla  a1, ec_invalid_nonce
	call send_error
	j    .Lauth_ret
.Lauth_replay_ok:
	# params entity
	mv   a0, s3
	lla  a1, ka_params
	li   a2, 6
	call map_find
	beqz a0, .Lauth_ret
	mv   s4, a0                     # params entity
	# params data map
	mv   a0, s4
	lla  a1, k_data
	li   a2, 4
	call map_find
	mv   s5, a0                     # params data (pdata)
	# §7.1 agility: reject an unsupported key_type at the handshake (400 unsupported_key_type)
	# before the identity checks. key_type must be the text "ed25519" (the core floor); any
	# other value — including the numeric 0xFD experimental code — is unsupported.
	mv   a0, s5
	lla  a1, ka_ktype
	li   a2, 8
	call map_find
	beqz a0, .Lauth_kt_ok            # absent → lenient (identity checks still run)
	call read_head                   # a0 = text ptr, a1 = major, a2 = len
	li   t0, 3
	bne  a1, t0, .Lauth_bad_kt       # must be a text string
	li   t0, 7
	bne  a2, t0, .Lauth_bad_kt
	lla  a1, v_ed25519
	li   a2, 7
	call memeq
	beqz a0, .Lauth_bad_kt
.Lauth_kt_ok:
	# client public_key → g_client_pubkey (32)
	mv   a0, s5
	lla  a1, ka_pubkey
	li   a2, 10
	call map_find
	call get_text                    # a0=ptr, a2=len(32)
	mv   a1, a0                      # src
	lla  a0, g_client_pubkey         # dst
	li   a2, 32
	call mcpy
	# grantee = ec_content_hash("system/peer", client_peer{key_type,public_key})
	lla  s6, b_clientpeer
	li   a1, 2
	call w_map
	lla  a0, ka_ktype
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_pubkey
	call w_cstr
	lla  a1, g_client_pubkey
	li   a2, 32
	call w_bstr
	# ec_content_hash(type, type_len, data, data_len, out) → a0..a4
	# (x86: rdi=type, rsi=type_len, rdx=data, rcx=data_len, r8=out)
	lla  a0, ta_peer
	li   a1, 11
	lla  a2, b_clientpeer
	lla  t0, b_clientpeer
	sub  a3, s6, t0                  # client peer data len
	lla  a4, g_grantee
	call ec_content_hash

	# ================= §5.2 verification (reject → 401) =================
	# 1. nonce echo — params.nonce must equal the nonce we issued (b_nonce)
	mv   a0, s5                      # pdata
	lla  a1, k_nonce
	li   a2, 5
	call map_find
	beqz a0, .Lauth_bad_nonce
	call get_text
	li   t0, 32
	bne  a2, t0, .Lauth_bad_nonce
	lla  a1, b_nonce
	li   a2, 32
	call memeq
	beqz a0, .Lauth_bad_nonce
	# 2. peer_id binding — base58(client pubkey) must equal params.peer_id
	# ec_peerid_format(key_type, hash_type, digest, digest_len, out, out_cap, out_len) → a0..a6
	li   a0, 1
	li   a1, 0
	lla  a2, g_client_pubkey
	li   a3, 32
	lla  a4, b_derived_pid
	li   a5, 128
	lla  a6, g_derived_pid_len
	call ec_peerid_format
	mv   a0, s5
	lla  a1, k_peerid
	li   a2, 7
	call map_find
	beqz a0, .Lauth_bad_pid
	call get_text                    # a0=ptr, a2=len
	lla  t0, g_derived_pid_len
	ld   t0, 0(t0)
	bne  a2, t0, .Lauth_bad_pid
	lla  a1, b_derived_pid
	# a2 already = len (the compare length)
	call memeq
	beqz a0, .Lauth_bad_pid
	# 2b. §4.7 row 8 names TWO inputs and this is the second: the authenticate's peer_id
	# must be the peer_id this connection was GREETED by. Rung 2 above proves the identity
	# is SELF-CONSISTENT (derived from its own public_key) and says nothing about whether
	# it is the identity we have been negotiating with — so with only rung 2 a caller may
	# greet as one peer and authenticate as another, and every seed-policy lookup afterwards
	# resolves against the wrong peer. Same row, same code: 401 identity_mismatch.
	# Vacuous when the hello named no peer_id; the field is optional there.
	lla  t0, g_hello_peer_len
	ld   t0, 0(t0)
	beqz t0, .Lauth_hello_bind_ok
	mv   a0, s5                      # pdata
	lla  a1, k_peerid
	li   a2, 7
	call map_find
	beqz a0, .Lauth_bad_pid
	call get_text                    # a0 = ptr, a2 = len
	lla  t0, g_hello_peer_len
	ld   t0, 0(t0)
	bne  a2, t0, .Lauth_bad_pid
	lla  a1, b_hello_peer
	call memeq
	beqz a0, .Lauth_bad_pid
.Lauth_hello_bind_ok:
	# 3. PoP signature — verify client sig over the authenticate entity content_hash
	mv   a0, s5
	call skip_value
	sub  t0, a0, s5                  # pdata len
	# ec_content_hash(type, type_len, data, data_len, out) → a0..a4
	lla  a0, ta_auth
	li   a1, 36
	mv   a2, s5                      # data = pdata
	mv   a3, t0                      # data_len
	lla  a4, g_auth_hash
	call ec_content_hash
	lla  a0, b_req
	lla  a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lauth_bad_sig
	call find_sig_entity
	beqz a0, .Lauth_bad_sig
	lla  a1, k_data
	li   a2, 4
	call map_find
	mv   s4, a0                      # sig data map
	mv   a0, s4
	lla  a1, ka_sig
	li   a2, 9
	call map_find
	call get_text                    # a0 = sig(64)
	mv   s1, a0
	# ec_ed25519_verify(pubkey, msg, msg_len, sig) → a0..a3
	lla  a0, g_client_pubkey
	lla  a1, g_auth_hash
	li   a2, 33
	mv   a3, s1
	call ec_ed25519_verify
	bnez a0, .Lauth_bad_sig
	# 4. impersonation — signature.signer must equal client identity_hash (grantee)
	mv   a0, s4
	lla  a1, ka_signer
	li   a2, 6
	call map_find
	call get_text
	lla  a1, g_grantee
	li   a2, 33
	call memeq
	beqz a0, .Lauth_bad_imp
	# ================= verification passed =================
	li   t0, 1
	lla  t1, g_authenticated
	sd   t0, 0(t1)

	call now_ms
	lla  t0, g_created
	sd   a0, 0(t0)

	# ---- token data ----
	lla  s6, b_tokdata
	li   a1, 4
	call w_map
	lla  a0, ka_grants
	call w_cstr
	call emit_grants
	lla  a0, ka_grantee
	call w_cstr
	lla  a1, g_grantee
	li   a2, 33
	call w_bstr
	lla  a0, ka_granter
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_created
	call w_cstr
	lla  t0, g_created
	ld   a1, 0(t0)
	call w_uint
	lla  t0, b_tokdata
	sub  a2, s6, t0
	lla  t0, g_toklen
	sd   a2, 0(t0)                   # token data len
	# tok_ch = ec_content_hash("system/capability/token", token_data)
	lla  a0, ta_token
	li   a1, 23
	lla  a2, b_tokdata
	lla  t0, g_toklen
	ld   a3, 0(t0)
	lla  a4, tok_ch
	call ec_content_hash
	# tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	lla  a0, g_seed
	lla  a1, tok_ch
	li   a2, 33
	lla  a3, tok_sig
	call ec_ed25519_sign

	# ---- signature entity data {signer,target,algorithm,signature} ----
	lla  s6, b_sigdata
	li   a1, 4
	call w_map
	lla  a0, ka_signer
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_target
	call w_cstr
	lla  a1, tok_ch
	li   a2, 33
	call w_bstr
	lla  a0, ka_algo
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_sig
	call w_cstr
	lla  a1, tok_sig
	li   a2, 64
	call w_bstr
	lla  t0, b_sigdata
	sub  a2, s6, t0
	lla  t0, g_sigdlen
	sd   a2, 0(t0)
	lla  a0, ta_sig
	li   a1, 16
	lla  a2, b_sigdata
	lla  t0, g_sigdlen
	ld   a3, 0(t0)
	lla  a4, sig_ch
	call ec_content_hash

	# ---- grant result data {token: tok_ch} ----
	lla  s6, b_grantdata
	li   a1, 1
	call w_map
	lla  a0, ka_token
	call w_cstr
	lla  a1, tok_ch
	li   a2, 33
	call w_bstr
	lla  t0, b_grantdata
	sub  a2, s6, t0
	lla  t0, g_grlen
	sd   a2, 0(t0)
	lla  a0, ta_grant
	li   a1, 23
	lla  a2, b_grantdata
	lla  t0, g_grlen
	ld   a3, 0(t0)
	lla  a4, grant_ch
	call ec_content_hash

	# ---- response data {result, status, request_id} ----
	lla  s6, b_ar_resp
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	# w_entity(type_cstr, data_ptr, data_len, chash_ptr) → a0..a3
	lla  a0, ta_grant                # result entity = the grant
	lla  a1, b_grantdata
	lla  t0, g_grlen
	ld   a2, 0(t0)
	lla  a3, grant_ch
	call w_entity
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_ar_resp
	sub  a2, s6, t0
	lla  t0, g_ardlen
	sd   a2, 0(t0)
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_ar_resp
	lla  t0, g_ardlen
	ld   a3, 0(t0)
	lla  a4, resp_ch2
	call ec_content_hash

	# ---- envelope {root, included} ----
	lla  s6, b_ar_env
	li   a1, 2
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_ar_resp
	lla  t0, g_ardlen
	ld   a2, 0(t0)
	lla  a3, resp_ch2
	call w_entity
	lla  a0, ka_included
	call w_cstr
	# Populate the included-entry table {key_ptr,type_ptr,data_ptr,data_len,ch_ptr}
	# then emit sorted by 33-byte key — ECF §4.2 canonical map ordering (the three
	# keys are content hashes, so the order is runtime-dependent). 40 bytes/entry.
	lla  a3, b_incl_tab
	# entry 0: token
	lla  t0, tok_ch
	sd   t0, 0(a3)
	lla  t0, ta_token
	sd   t0, 8(a3)
	lla  t0, b_tokdata
	sd   t0, 16(a3)
	lla  t0, g_toklen
	ld   t0, 0(t0)
	sd   t0, 24(a3)
	lla  t0, tok_ch
	sd   t0, 32(a3)
	# entry 1: peer (identity)
	lla  t0, g_identity_hash
	sd   t0, 40(a3)
	lla  t0, ta_peer
	sd   t0, 48(a3)
	lla  t0, b_peerdata
	sd   t0, 56(a3)
	lla  t0, g_peerdata_len
	ld   t0, 0(t0)
	sd   t0, 64(a3)
	lla  t0, g_identity_hash
	sd   t0, 72(a3)
	# entry 2: signature
	lla  t0, sig_ch
	sd   t0, 80(a3)
	lla  t0, ta_sig
	sd   t0, 88(a3)
	lla  t0, b_sigdata
	sd   t0, 96(a3)
	lla  t0, g_sigdlen
	ld   t0, 0(t0)
	sd   t0, 104(a3)
	lla  t0, sig_ch
	sd   t0, 112(a3)
	li   a0, 3
	lla  a1, b_incl_tab
	call emit_sorted_included
	# frame + write
	lla  t0, b_ar_env
	sub  s5, s6, t0                 # env len
	bswap32 t0, s5
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_ar_env
	mv   a2, s5
	call write_all
	j    .Lauth_ret
.Lauth_bad_nonce:
	li   a0, 401
	lla  a1, ec_invalid_nonce
	call send_error
	j    .Lauth_ret
.Lauth_bad_pid:
	li   a0, 401
	lla  a1, ec_identity_mismatch
	call send_error
	j    .Lauth_ret
.Lauth_bad_sig:
	li   a0, 401
	lla  a1, ec_auth_failed
	call send_error
	j    .Lauth_ret
.Lauth_bad_imp:
	li   a0, 401
	lla  a1, ec_identity_mismatch
	call send_error
	j    .Lauth_ret
.Lauth_bad_kt:
	li   a0, 400
	lla  a1, ec_unsup_kt
	call send_error
.Lauth_ret:
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret
# Authorizes the caller with the same §5.2 gate as the get path (401/403 on failure), then
# mints a token whose grants are copied verbatim from params.data.grants (the caller asks for
# the attenuation it wants), grantee = the request author, granter = this peer; signs it and
# returns a 200 system/capability/grant with {token, granter-peer, signature} in included.
	.type build_request_response, @function
build_request_response:
	# s3=exec, s4=grants value ptr, s5=caller cap hash, s6=CBOR cursor (global).
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s3, 16(sp)
	sd   s4, 24(sp)
	sd   s5, 32(sp)
	sd   s6, 40(sp)
	mv   s0, sp
	mv   s3, a0                     # exec
	# authorize: auth-class (401) then capability + grant-scope (403). The handler derived
	# from data.uri is system/capability, op is request — the authenticate-minted floor
	# token grants exactly that, so a legitimately-authenticated caller passes.
	mv   a0, s3
	call verify_get_auth
	bnez a0, .Lrq_ret
	mv   a0, s3
	call verify_get_cap
	bnez a0, .Lrq_ret
	mv   a0, s3
	call verify_op_scope
	bnez a0, .Lrq_ret
	# grantee = request author (33) → g_grantee
	mv   a0, s3
	lla  a1, k_author
	li   a2, 6
	call map_find
	beqz a0, .Lrq_malformed
	call get_text
	# mcpy(a0=dst, a1=src, a2=len): get_text returns bytes ptr in a0, so route it as src.
	mv   t0, a0                     # src (get_text bytes ptr)
	lla  a0, g_grantee             # dst
	mv   a1, t0                    # src
	li   a2, 33
	call mcpy
	# requested grants = params.data.grants (raw CBOR array) → g_reqg_ptr/len
	mv   a0, s3
	lla  a1, ka_params
	li   a2, 6
	call map_find
	beqz a0, .Lrq_malformed
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lrq_malformed
	lla  t0, g_params_data          # params.data — the §5.6 ttl_ms term lives here
	sd   a0, 0(t0)
	lla  a1, ka_grants
	li   a2, 6
	call map_find
	beqz a0, .Lrq_malformed
	mv   s4, a0                     # grants value ptr
	call skip_value                  # a0 = end of grants value
	sub  a0, a0, s4                 # grants byte length
	lla  t0, g_reqg_ptr
	sd   s4, 0(t0)
	lla  t0, g_reqg_len
	sd   a0, 0(t0)
	# attenuation (§6.2): the requested grants MUST NOT widen scope beyond the caller's
	# token. Resolve the caller's token data (data.capability → included) and require every
	# requested grant to be covered by some caller grant, else 403 capability_denied.
	mv   a0, s3
	lla  a1, k_capability
	li   a2, 10
	call map_find
	beqz a0, .Lrq_denied
	call get_text
	mv   s5, a0                     # caller cap hash
	lla  a0, b_req
	lla  a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lrq_denied
	mv   a1, s5
	call included_find_by_key
	beqz a0, .Lrq_denied
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lrq_denied
	mv   a1, a0                     # caller token data
	lla  t0, g_caller_td
	sd   a1, 0(t0)
	mv   a0, s4                     # requested grants array value
	call grants_attenuated
	bnez a0, .Lrq_atten_ok
.Lrq_denied:
	li   a0, 403
	lla  a1, ec_cap_denied
	call send_error
	j    .Lrq_ret
.Lrq_atten_ok:
	# created_at — sampled ONCE. The duration term below is converted against this same
	# instant; sampling again there emits a token whose stated birth and derived expiry are
	# two different instants.
	call now_ms
	lla  t0, g_created
	sd   a0, 0(t0)
	# ---- §6.2 CAP-5 / §5.6 MIN_DEFINED mint ceiling ----
	#
	#   expires_at = MIN_DEFINED( caller_capability.expires_at,   ; ABSOLUTE, enters directly
	#                             created_at + request.ttl_ms )   ; DURATION, converted first
	#
	# `request` mints a ROOT token (parent: null), so §5.6's parent-child attenuation never
	# reaches it — without this clamp, temporal attenuation is the one dimension a requester
	# could escape and policy withdrawal would have no bounded latency. This is NOT an
	# authorization decision: an over-long ttl_ms from a bounded caller MINTS the clamped
	# value and returns 200, and refusing it is non-conformant.
	#
	# The value is reached BY CONSTRUCTION, not by comparison. A `<= caller_exp` check
	# satisfies a strictly weaker test than the one being run — the oracle says so in its own
	# failure text — so there is deliberately no comparison against the caller's expiry here.
	#
	# §5.6's third term, `created_at + policy_entry.ttl_ms`, is structurally absent on this
	# peer: it writes policy entries (§6.2 configure) but never reads one back on the request
	# path, so there is no policy entry in scope to take a ttl from. That is a missing TERM,
	# not a missing rule — MIN_DEFINED over the terms that exist is exactly what it computes.
	lla  t0, g_exp_have
	sd   zero, 0(t0)
	lla  t0, g_expv
	sd   zero, 0(t0)
	lla  t0, g_caller_td
	ld   a0, 0(t0)
	beqz a0, .Lrq_ttl
	lla  a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lrq_ttl
	call read_head
	bnez a1, .Lrq_ttl               # not a uint64 → unusable, not a term
	lla  t0, g_expv
	sd   a2, 0(t0)
	li   t1, 1
	lla  t0, g_exp_have
	sd   t1, 0(t0)
.Lrq_ttl:
	lla  t0, g_params_data
	ld   a0, 0(t0)
	beqz a0, .Lrq_mint
	lla  a1, ka_ttl_ms
	li   a2, 6
	call map_find
	beqz a0, .Lrq_mint
	call read_head
	bnez a1, .Lrq_mint
	lla  t0, g_created
	ld   t0, 0(t0)
	add  t1, t0, a2                 # created_at + ttl_ms
	# §5.6 rule 3: a term that does not fit is DROPPED — never wrapped, never saturated.
	# Saturation would manufacture expires_at == 2^64-1, a finite bound no reader can tell
	# from a deliberate one. RISC-V has no carry flag, so unsigned overflow is detected the
	# way the ISA intends: the sum wrapped iff it is less than either operand.
	# ttl_ms == 0 is NOT special-cased (rule 2): it falls out as created_at, which is what
	# keeps "expire immediately" from collapsing into the absent / "no bound" spelling.
	bltu t1, t0, .Lrq_mint
	lla  t2, g_exp_have
	ld   t2, 0(t2)
	bnez t2, .Lrq_ttl_min
	lla  t0, g_expv
	sd   t1, 0(t0)
	li   t2, 1
	lla  t0, g_exp_have
	sd   t2, 0(t0)
	j    .Lrq_mint
.Lrq_ttl_min:
	lla  t0, g_expv
	ld   t2, 0(t0)
	bgeu t1, t2, .Lrq_mint
	sd   t1, 0(t0)
.Lrq_mint:
	# ---- token data {grants:<raw>, grantee, granter, created_at[, expires_at]} ----
	# Canonical key order is length-then-lex, so expires_at sorts AFTER created_at (same
	# length, c < e) and appends cleanly at the end.
	lla  s6, b_tokdata
	lla  t0, g_exp_have
	ld   a1, 0(t0)
	addi a1, a1, 4
	call w_map
	lla  a0, ka_grants
	call w_cstr
	lla  t0, g_reqg_ptr
	ld   a1, 0(t0)
	lla  t0, g_reqg_len
	ld   a2, 0(t0)
	call w_raw
	lla  a0, ka_grantee
	call w_cstr
	lla  a1, g_grantee
	li   a2, 33
	call w_bstr
	lla  a0, ka_granter
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_created
	call w_cstr
	lla  t0, g_created
	ld   a1, 0(t0)
	call w_uint
	lla  t0, g_exp_have
	ld   t0, 0(t0)
	beqz t0, .Lrq_tokdone
	lla  a0, ka_expires
	call w_cstr
	lla  t0, g_expv
	ld   a1, 0(t0)
	call w_uint
.Lrq_tokdone:
	lla  t0, b_tokdata
	sub  a2, s6, t0                 # token data len
	lla  t0, g_toklen
	sd   a2, 0(t0)
	# shared tail: hash+sign the token, build the grant, emit the 200 response.
	call mint_finish
	j    .Lrq_ret
.Lrq_malformed:
	# §4.9(c) deliver-or-signal: a `request` missing author / params / params.data /
	# params.data.grants used to fall off the end of this function and answer NOTHING,
	# leaving the caller to wait out its own timeout — indistinguishable from a dead peer.
	# The branch was unreachable for as long as the capability gate refused every delegated
	# capability two stages earlier; implementing the §5.5 chain walk is what let a request
	# get this far, which is the standing lesson in the other direction — a wrong denial can
	# also hide a missing ANSWER, not just a missing check.
	li   a0, 400
	lla  a1, ec_invalid_params
	call send_error
.Lrq_ret:
	ld   s6, 40(sp)
	ld   s5, 32(sp)
	ld   s4, 24(sp)
	ld   s3, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# mint_finish — shared token-grant tail (globals-only): given b_tokdata/g_toklen already
# built (and g_grantee consumed into it), compute the token content_hash, Ed25519-sign it as
# this peer, build the system/signature entity + the system/capability/grant result, and emit
# the 200 EXECUTE_RESPONSE with {token, granter-peer, signature} sorted into `included`.
# Used by build_request_response; build_authenticate_response keeps its own inline copy.
	.type mint_finish, @function
mint_finish:
	# s5 = env len (survives write_all), s6 = CBOR cursor (global).
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s5, 16(sp)
	sd   s6, 24(sp)
	mv   s0, sp
	# tok_ch = ec_content_hash("system/capability/token", token_data)
	lla  a0, ta_token
	li   a1, 23
	lla  a2, b_tokdata
	lla  t0, g_toklen
	ld   a3, 0(t0)
	lla  a4, tok_ch
	call ec_content_hash
	# tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	lla  a0, g_seed
	lla  a1, tok_ch
	li   a2, 33
	lla  a3, tok_sig
	call ec_ed25519_sign
	# ---- signature entity data {signer,target,algorithm,signature} ----
	lla  s6, b_sigdata
	li   a1, 4
	call w_map
	lla  a0, ka_signer
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_target
	call w_cstr
	lla  a1, tok_ch
	li   a2, 33
	call w_bstr
	lla  a0, ka_algo
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_sig
	call w_cstr
	lla  a1, tok_sig
	li   a2, 64
	call w_bstr
	lla  t0, b_sigdata
	sub  a2, s6, t0                 # sig data len
	lla  t0, g_sigdlen
	sd   a2, 0(t0)
	lla  a0, ta_sig
	li   a1, 16
	lla  a2, b_sigdata
	lla  t0, g_sigdlen
	ld   a3, 0(t0)
	lla  a4, sig_ch
	call ec_content_hash
	# ---- grant result data {token: tok_ch} ----
	lla  s6, b_grantdata
	li   a1, 1
	call w_map
	lla  a0, ka_token
	call w_cstr
	lla  a1, tok_ch
	li   a2, 33
	call w_bstr
	lla  t0, b_grantdata
	sub  a2, s6, t0                 # grant data len
	lla  t0, g_grlen
	sd   a2, 0(t0)
	lla  a0, ta_grant
	li   a1, 23
	lla  a2, b_grantdata
	lla  t0, g_grlen
	ld   a3, 0(t0)
	lla  a4, grant_ch
	call ec_content_hash
	# ---- response data {result, status, request_id} ----
	lla  s6, b_ar_resp
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	lla  a0, ta_grant
	lla  a1, b_grantdata
	lla  t0, g_grlen
	ld   a2, 0(t0)
	lla  a3, grant_ch
	call w_entity
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_ar_resp
	sub  a2, s6, t0                 # response data len
	lla  t0, g_ardlen
	sd   a2, 0(t0)
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_ar_resp
	lla  t0, g_ardlen
	ld   a3, 0(t0)
	lla  a4, resp_ch2
	call ec_content_hash
	# ---- envelope {root, included} ----
	lla  s6, b_ar_env
	li   a1, 2
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_ar_resp
	lla  t0, g_ardlen
	ld   a2, 0(t0)
	lla  a3, resp_ch2
	call w_entity
	lla  a0, ka_included
	call w_cstr
	lla  a3, b_incl_tab            # table base (a3, since a0/a1/a2 feed emit_sorted_included)
	# entry 0: token
	lla  t0, tok_ch
	sd   t0, 0(a3)
	lla  t0, ta_token
	sd   t0, 8(a3)
	lla  t0, b_tokdata
	sd   t0, 16(a3)
	lla  t1, g_toklen
	ld   t0, 0(t1)
	sd   t0, 24(a3)
	lla  t0, tok_ch
	sd   t0, 32(a3)
	# entry 1: peer (identity)
	lla  t0, g_identity_hash
	sd   t0, 40(a3)
	lla  t0, ta_peer
	sd   t0, 48(a3)
	lla  t0, b_peerdata
	sd   t0, 56(a3)
	lla  t1, g_peerdata_len
	ld   t0, 0(t1)
	sd   t0, 64(a3)
	lla  t0, g_identity_hash
	sd   t0, 72(a3)
	# entry 2: signature
	lla  t0, sig_ch
	sd   t0, 80(a3)
	lla  t0, ta_sig
	sd   t0, 88(a3)
	lla  t0, b_sigdata
	sd   t0, 96(a3)
	lla  t1, g_sigdlen
	ld   t0, 0(t1)
	sd   t0, 104(a3)
	lla  t0, sig_ch
	sd   t0, 112(a3)
	li   a0, 3
	lla  a1, b_incl_tab
	call emit_sorted_included
	# frame + write
	lla  t0, b_ar_env
	sub  s5, s6, t0               # env len
	bswap32 t0, s5               # big-endian length prefix
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_ar_env
	mv   a2, s5
	call write_all
	ld   s6, 24(sp)
	ld   s5, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret
# store_put's arena/index caps are defined by the data fragment (10_data1.s) that precedes
# this one in the concatenated dispatch.s. They are used here as bare immediates, so guard-
# define them for the isolated per-fragment check; when 10_data1.s already defined them the
# .ifndef skips these copies (no effect on the real build).
	.ifndef STORE_MAX
	.equ STORE_MAX,   8192
	.endif
	.ifndef STORE_ARENA_CAP
	.equ STORE_ARENA_CAP, 67108864
	.endif

# send_error(a0=status, a1=code_cstr) — emit a status EXECUTE_RESPONSE with a
# system/protocol/error {code} result. No `included`.
	.type send_error, @function
send_error:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)
	mv   s0, sp
	mv   s3, a0                     # status
	mv   s4, a1                     # code cstr
	lla  s6, b_err
	li   a1, 1
	call w_map
	lla  a0, k_code
	call w_cstr
	mv   a0, s4
	call w_cstr
	lla  t0, b_err
	sub  s5, s6, t0                # err data len
	lla  a0, t_error
	li   a1, 21
	lla  a2, b_err
	mv   a3, s5
	lla  a4, err_ch
	call ec_content_hash
	lla  s6, b_er_resp
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	lla  a0, t_error
	lla  a1, b_err
	mv   a2, s5
	lla  a3, err_ch
	call w_entity
	lla  a0, k_status
	call w_cstr
	mv   a1, s3
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_er_resp
	sub  s5, s6, t0                # resp data len
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_er_resp
	mv   a3, s5
	lla  a4, er_resp_ch
	call ec_content_hash
	lla  s6, b_er_env
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_er_resp
	mv   a2, s5
	lla  a3, er_resp_ch
	call w_entity
	lla  t0, b_er_env
	sub  s5, s6, t0                # env len
	bswap32 t0, s5
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_er_env
	mv   a2, s5
	call write_all
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# serve_tree_get(a0 = exec data map ptr) — resolve resource.targets[0] against the
# embedded read-only type/handler store; 200 with the stored entity, else 404.
# =====================================================================
	.type serve_tree_get, @function
# chain_depth_check(a0 = exec data map) -> a0 = 0 ok, 1 rejected (400 chain_depth_exceeded).
# §9.1/§4.10(b) resource floor: follow the presented capability's `parent` chain through
# `included`; a chain deeper than 64 delegations is rejected before the authority walk. A
# cyclic chain terminates the same way (depth passes 64). Server-minted tokens carry no
# parent (depth 0), so the type_system cohort is untouched.
	.type chain_depth_check, @function
chain_depth_check:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s4, a0                    # exec
	lla  a1, k_capability
	li   a2, 10
	call map_find
	beqz a0, .Lcd_ok               # no capability → nothing to bound
	call get_text
	mv   s3, a0                    # cur = capability hash ptr (33)
	lla  a0, b_req
	lla  a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lcd_ok
	mv   s2, a0                    # included
	li   s1, 0                     # depth = 0
.Lcd_loop:
	mv   a0, s2
	mv   a1, s3
	call included_find_by_key
	beqz a0, .Lcd_ok              # chain ends (unresolvable) → depth within bound
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lcd_ok
	lla  a1, ka_parent
	li   a2, 6
	call map_find
	beqz a0, .Lcd_ok             # root reached (no parent) → within bound
	call get_text
	mv   s3, a0                  # cur = parent hash
	addi s1, s1, 1
	li   t0, 64
	bleu s1, t0, .Lcd_loop       # ≤64 delegations → keep walking
	li   a0, 400
	lla  a1, ec_chain_depth
	call send_error
	li   a0, 1
	j    .Lcd_ret
.Lcd_ok:
	li   a0, 0
.Lcd_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

	.type serve_tree_get, @function
serve_tree_get:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s3, a0                    # exec data map
	# §9.1/§4.10(b) resource floor — reject an over-deep delegation chain (400) up front,
	# before the authority walk, so a maliciously deep chain can't force unbounded work.
	mv   a0, s3
	call chain_depth_check
	bnez a0, .Lstg_done           # 400 chain_depth_exceeded already sent
	# §5.2 auth-class gate — reject unauthenticated/tampered requests (401) before serving.
	mv   a0, s3
	call verify_get_auth          # a0 = exec
	bnez a0, .Lstg_done           # rejected; 401 already sent
	# §5.2 capability-class gate (403) — token present/bound/signed.
	mv   a0, s3
	call verify_get_cap
	bnez a0, .Lstg_done           # rejected; 403 already sent
	# §5.2 grant-scope gate (403 default-deny) — token must permit op×handler×resource.
	mv   a0, s3
	call verify_get_scope
	bnez a0, .Lstg_done           # rejected; 403 already sent
	# resource = map_find(exec, "resource", 8)
	mv   a0, s3
	lla  a1, k_resource
	li   a2, 8
	call map_find
	beqz a0, .Lstg_404
	# targets = map_find(resource, "targets", 7)
	lla  a1, k_targets
	li   a2, 7
	call map_find
	beqz a0, .Lstg_404
	# a0 = targets array value; read head, require ≥1 element
	call read_head                # a0=after-head, a1=major(4), a2=count
	beqz a2, .Lstg_404
	# first element is a text string → ptr,len
	call get_text                 # a0=strptr, a2=strlen
	mv   s1, a0                  # raw target ptr
	mv   s2, a2                  # raw target len
	# §"invalid_path" reject (dot-relative / empty-segment / NUL).
	mv   a1, s1
	mv   a3, s2
	call path_valid
	beqz a0, .Lstg_invalid
	# empty target (root) or trailing '/' → listing over the store (§tree get listing).
	beqz s2, .Lstg_listing        # empty = root listing
	add  t0, s1, s2
	lbu  t0, -1(t0)              # last byte
	li   t1, 0x2f                # '/'?
	bne  t0, t1, .Lstg_point
.Lstg_listing:
	mv   a0, s1
	mv   a1, s2
	call serve_tree_listing       # emits its own 200/404
	j    .Lstg_done
.Lstg_point:
	# §1.4 canonicalize for the write-store key; the read-only typestore keeps raw keys.
	mv   a1, s1
	mv   a3, s2
	call canon_path               # a0=canon ptr, a2=canon len
	mv   a1, a0
	mv   a3, a2
	call store_get                # -> a0=blob|0, a2=len
	bnez a0, .Lstg_send
	mv   a1, s1                  # raw target for the read-only typestore
	mv   a3, s2
	call typestore_lookup         # -> a0=blobptr|0, a2=bloblen
	beqz a0, .Lstg_404
.Lstg_send:
	mv   a1, a2
	call send_get_ok
	j    .Lstg_done
.Lstg_invalid:
	li   a0, 400
	lla  a1, ec_invalid_path
	call send_error
	j    .Lstg_done
.Lstg_404:
	li   a0, 404
	lla  a1, ec_not_found
	call send_error
.Lstg_done:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# typestore_lookup(a1 = target ptr, a3 = target len) -> a0 = blob ptr|0, a2 = blob len.
# Linear scan of the generated type_table (the core floor, currently 58 entries;
# the count is read from type_table_count, never assumed); exact string match on the path
# (the listing path "system/type/" carries its trailing slash, so it matches verbatim too).
	.type typestore_lookup, @function
typestore_lookup:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s3, a1                    # target ptr
	mv   s4, a3                    # target len
	lla  s1, type_table
	lla  t0, type_table_count
	ld   s2, 0(t0)
.Ltl_loop:
	beqz s2, .Ltl_none
	ld   t0, 8(s1)                # entry.path_len
	bne  t0, s4, .Ltl_next
	ld   a0, 0(s1)               # entry.path_ptr
	mv   a1, s3
	mv   a2, s4
	call memeq
	bnez a0, .Ltl_found
.Ltl_next:
	addi s1, s1, 32
	addi s2, s2, -1
	j    .Ltl_loop
.Ltl_found:
	ld   a0, 16(s1)             # entry.blob_ptr
	ld   a2, 24(s1)             # entry.blob_len
	j    .Ltl_ret
.Ltl_none:
	li   a0, 0
	li   a2, 0
.Ltl_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# send_get_ok(a0 = entity blob ptr, a1 = entity blob len) — emit a 200 EXECUTE_RESPONSE
# whose `result` is the pre-serialized stored entity, copied verbatim (w_raw). Mirrors
# send_error's envelope construction.
	.type send_get_ok, @function
send_get_ok:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s6, 40(sp)
	mv   s0, sp
	mv   s1, a0                    # blob ptr
	mv   s2, a1                    # blob len
	# ---- data map {result:<blob>, status:200, request_id:<rid>} ----
	lla  s6, b_get_data
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	mv   a1, s1
	mv   a2, s2
	call w_raw
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_get_data
	sub  s3, s6, t0              # s3 = data len
	# content_hash of the response entity
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_get_data
	mv   a3, s3
	lla  a4, get_data_ch
	call ec_content_hash
	# ---- envelope {root: <resp entity>} ----
	lla  s6, b_get_env
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_get_data
	mv   a2, s3
	lla  a3, get_data_ch
	call w_entity
	# ---- frame (4-byte BE len) + send ----
	lla  t0, b_get_env
	sub  s3, s6, t0
	bswap32 t0, s3
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_get_env
	mv   a2, s3
	call write_all
	ld   s6, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# =====================================================================
# A-ASM-011 — per-fork write store (path→entity). store_idx is an array of 32-byte entries
# [0]=path_ptr [8]=path_len [16]=blob_ptr [24]=blob_len, pointing into store_arena where the
# bytes are copied out of the per-frame-reused b_req so they persist across the connection.
# =====================================================================

# store_get(a1 = path ptr, a3 = path len) -> a0 = blob ptr|0, a2 = blob len.
# Preserves a1/a3 so the caller can fall through to the read-only typestore_lookup.
	.type store_get, @function
store_get:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s3, a1                    # path ptr
	mv   s4, a3                    # path len
	lla  s1, store_idx
	lla  t0, store_count
	ld   s2, 0(t0)
.Lsg_loop:
	beqz s2, .Lsg_none
	ld   t0, 8(s1)                # entry.path_len
	bne  t0, s4, .Lsg_next
	ld   a0, 0(s1)               # entry.path_ptr
	mv   a1, s3
	mv   a2, s4
	call memeq
	bnez a0, .Lsg_found
.Lsg_next:
	addi s1, s1, 32
	addi s2, s2, -1
	j    .Lsg_loop
.Lsg_found:
	ld   a0, 16(s1)             # blob ptr
	ld   a2, 24(s1)             # blob len
	j    .Lsg_ret
.Lsg_none:
	li   a0, 0
	li   a2, 0
.Lsg_ret:
	mv   a1, s3                  # restore path ptr/len for the caller's fallback
	mv   a3, s4
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# store_put(a0 = path ptr, a1 = path len, a2 = blob ptr, a3 = blob len).
# Overwrites an existing binding in place (new blob appended to the arena), else appends a
# new entry. s7 holds the scan counter across memeq (memeq never touches s7).
	.type store_put, @function
store_put:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	mv   s0, sp
	mv   s1, a0                    # path ptr
	mv   s2, a1                    # path len
	mv   s3, a2                    # blob ptr
	mv   s4, a3                    # blob len
	# arena capacity guard — never write past store_arena (would corrupt neighbouring .bss).
	lla  t0, store_used
	ld   t0, 0(t0)
	add  t0, t0, s2
	add  t0, t0, s4
	li   t1, STORE_ARENA_CAP
	bgtu t0, t1, .Lsp_ret
	lla  s5, store_idx
	lla  t0, store_count
	ld   s7, 0(t0)
.Lsp_scan:
	beqz s7, .Lsp_new
	ld   t0, 8(s5)               # entry.path_len
	bne  t0, s2, .Lsp_scan_next
	ld   a0, 0(s5)
	mv   a1, s1
	mv   a2, s2
	call memeq
	bnez a0, .Lsp_overwrite
.Lsp_scan_next:
	addi s5, s5, 32
	addi s7, s7, -1
	j    .Lsp_scan
.Lsp_overwrite:
	# s5 = matching entry — append new blob to the arena, repoint the entry.
	lla  a0, store_arena
	lla  t0, store_used
	ld   t0, 0(t0)
	add  a0, a0, t0
	sd   a0, 16(s5)             # entry.blob_ptr = dst
	sd   s4, 24(s5)             # entry.blob_len
	mv   a1, s3
	mv   a2, s4
	call mcpy
	lla  t0, store_used
	ld   t1, 0(t0)
	add  t1, t1, s4
	sd   t1, 0(t0)
	j    .Lsp_ret
.Lsp_new:
	lla  t0, store_count
	ld   t0, 0(t0)
	li   t1, STORE_MAX
	bgeu t0, t1, .Lsp_ret       # index-full guard — drop rather than overrun store_idx
	slli t0, t0, 5              # *32
	lla  s5, store_idx
	add  s5, s5, t0            # s5 = new entry slot
	lla  a0, store_arena
	lla  t0, store_used
	ld   t0, 0(t0)
	add  a0, a0, t0            # dst = arena + used
	sd   a0, 0(s5)             # entry.path_ptr
	sd   s2, 8(s5)             # entry.path_len
	mv   a1, s1               # path src
	mv   a2, s2
	call mcpy                  # a0 = dst + path_len = blob dst
	sd   a0, 16(s5)           # entry.blob_ptr
	sd   s4, 24(s5)           # entry.blob_len
	mv   a1, s3               # blob src
	mv   a2, s4
	call mcpy
	lla  t0, store_used
	ld   t1, 0(t0)
	add  t1, t1, s2
	add  t1, t1, s4
	sd   t1, 0(t0)
	lla  t0, store_count
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
.Lsp_ret:
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# canon_path(a1 = path ptr, a3 = path len) -> a0 = canon ptr, a2 = canon len.
# §1.4 universal address space: a peer-relative path `foo` canonicalizes to the absolute
# `/{localPeerID}/foo`; an already-absolute `/…` path (incl. foreign namespaces) is verbatim.
# Relative results are built into b_canon; absolute results alias the input.
	.type canon_path, @function
canon_path:
	beqz a3, .Lcp_asis
	lbu  t0, 0(a1)                 # leading byte
	li   t1, 0x2f                  # '/' → already absolute
	beq  t0, t1, .Lcp_asis
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a1                    # path ptr
	mv   s2, a3                    # path len
	lla  s3, b_canon
	li   t0, 0x2f                  # '/'
	sb   t0, 0(s3)
	addi s3, s3, 1
	mv   a0, s3
	lla  a1, g_peerid
	lla  t0, g_peerid_len
	ld   a2, 0(t0)
	call mcpy                       # a0 = dst end
	mv   s3, a0
	li   t0, 0x2f                  # '/'
	sb   t0, 0(s3)
	addi s3, s3, 1
	mv   a0, s3
	mv   a1, s1
	mv   a2, s2
	call mcpy                       # a0 = end of canon
	lla  t0, b_canon
	sub  a2, a0, t0                 # a2 = canon len
	lla  a0, b_canon              # a0 = canon ptr
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret
.Lcp_asis:
	mv   a0, a1
	mv   a2, a3
	ret

# path_valid(a1 = path ptr, a3 = path len) -> a0 = 1 valid / 0 invalid.
# §"invalid_path": rejects a NUL byte, an empty non-leading segment ("//"), and any "."/".."
# segment (dot-relative). A single trailing '/' (listing) and a single leading '/' (absolute)
# are allowed; Unicode segments are accepted (only the byte rules above apply).
	.type path_valid, @function
path_valid:
	# §1.4: caller-supplied paths are peer-relative; a leading '/' means an absolute
	# /{peerID}/… address, so the first segment must be peer-id-length. A short leading
	# segment ("/system/…") is a mis-scoped caller path → invalid_path.
	beqz a3, .Lpv_body
	lbu  t0, 0(a1)
	li   t1, 0x2f
	bne  t0, t1, .Lpv_body
	li   a4, 1
.Lpv_fs:
	bgeu a4, a3, .Lpv_fsdone
	add  t0, a1, a4
	lbu  t0, 0(t0)
	li   t1, 0x2f
	beq  t0, t1, .Lpv_fsdone
	addi a4, a4, 1
	j    .Lpv_fs
.Lpv_fsdone:
	addi a4, a4, -1                 # first-segment length
	li   t0, 32
	bltu a4, t0, .Lpv_bad
.Lpv_body:
	li   a4, 0                      # i
	li   a5, 0                      # seg_start
.Lpv_loop:
	bgeu a4, a3, .Lpv_final
	add  t0, a1, a4
	lbu  t0, 0(t0)
	beqz t0, .Lpv_bad             # NUL
	li   t1, 0x2f                 # '/'
	bne  t0, t1, .Lpv_next
	sub  t1, a4, a5              # seg_len
	bnez t1, .Lpv_checkdot
	bnez a5, .Lpv_bad           # empty segment: OK only when leading (seg_start==0)
	j    .Lpv_advance
.Lpv_checkdot:
	li   t2, 1
	bne  t1, t2, .Lpv_checkdd
	add  t0, a1, a5
	lbu  t0, 0(t0)
	li   t2, 0x2e                # "."
	beq  t0, t2, .Lpv_bad
	j    .Lpv_advance
.Lpv_checkdd:
	li   t2, 2
	bne  t1, t2, .Lpv_advance
	add  t0, a1, a5
	lbu  t0, 0(t0)
	li   t2, 0x2e
	bne  t0, t2, .Lpv_advance
	addi t0, a5, 1
	add  t0, a1, t0
	lbu  t0, 0(t0)
	li   t2, 0x2e               # ".."
	beq  t0, t2, .Lpv_bad
.Lpv_advance:
	addi a5, a4, 1
.Lpv_next:
	addi a4, a4, 1
	j    .Lpv_loop
.Lpv_final:
	sub  t1, a3, a5              # final seg len
	beqz t1, .Lpv_ok            # trailing '/' or empty → allow
	li   t2, 1
	bne  t1, t2, .Lpv_fdd
	add  t0, a1, a5
	lbu  t0, 0(t0)
	li   t2, 0x2e
	beq  t0, t2, .Lpv_bad
	j    .Lpv_ok
.Lpv_fdd:
	li   t2, 2
	bne  t1, t2, .Lpv_ok
	add  t0, a1, a5
	lbu  t0, 0(t0)
	li   t2, 0x2e
	bne  t0, t2, .Lpv_ok
	addi t0, a5, 1
	add  t0, a1, t0
	lbu  t0, 0(t0)
	li   t2, 0x2e
	beq  t0, t2, .Lpv_bad
.Lpv_ok:
	li   a0, 1
	ret
.Lpv_bad:
	li   a0, 0
	ret

# cas_check(a0 = params.data map, a1 = path ptr, a2 = path len) -> a0 = 0 ok / 1 conflict.
# §"tree put" CAS: expected_hash absent → unconditional. all-zero(33B) → path must be ABSENT
# (create). nonzero → path must exist and its entity's content_hash must equal expected_hash.
	.type cas_check, @function
cas_check:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s3, a1                    # path ptr
	mv   s4, a2                    # path len
	mv   s2, a0                    # params.data
	mv   a0, s2
	lla  a1, k_expected
	li   a2, 13
	call map_find
	beqz a0, .Lcas_ok            # absent → unconditional put
	call get_text               # a0=exp ptr, a2=exp len
	mv   s5, a0                 # expected hash ptr
	mv   a3, a2                 # exp len
	li   s1, 0                   # OR-accumulator (0 ⇒ all-zero)
	li   t0, 0
.Lcas_zscan:
	bgeu t0, a3, .Lcas_zdone
	add  t1, s5, t0
	lbu  t1, 0(t1)
	or   s1, s1, t1
	addi t0, t0, 1
	j    .Lcas_zscan
.Lcas_zdone:
	mv   a1, s3
	mv   a3, s4
	call store_get              # a0=cur blob|0, a2=len
	bnez s1, .Lcas_nonzero
	# expected all-zero → require ABSENT
	bnez a0, .Lcas_conflict
	j    .Lcas_ok
.Lcas_nonzero:
	# require PRESENT with matching content_hash
	beqz a0, .Lcas_conflict
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lcas_conflict
	call get_text               # a0=cur chash ptr
	mv   a1, s5
	li   a2, 33
	call memeq
	beqz a0, .Lcas_conflict
	j    .Lcas_ok
.Lcas_conflict:
	li   a0, 1
	j    .Lcas_ret
.Lcas_ok:
	li   a0, 0
.Lcas_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret
# =====================================================================
# =====================================================================
# admit_put(a0 = submitted entity value) -> a0: 0 admitted · 1 invalid_request
# · 2 unsupported_content_hash_format · 3 hash_mismatch
#
# §6.3's put admission ladder (normative, 0.8.2.11). `put` is a RECEIPT path: the
# submitter authors the entity, the peer validates what it received (§1.8 item 1)
# and MUST NOT author a submitted entity's content_hash on the submitter's behalf.
# Two ORDERED steps, and the order is a data dependency rather than a choice —
# step 2's inputs are exactly what step 1 establishes, so a submission that is both
# malformed and mis-hashed is step 1's and answers invalid_request.
#   1. STRUCTURE — a map with a non-empty text `type`, a PRESENT `data` (any CBOR
#      value; null is legal), and a `content_hash` that is a well-formed system/hash
#      whose total byte length matches its format code (§1.2). Any failure ->
#      invalid_request; a well-formed hash naming a format code this peer cannot
#      VERIFY is the separate §1.2 row -> unsupported_content_hash_format. The
#      ec_content_hash FFI is the SHA-256 floor, so 0x00 is the whole verifiable set.
#   2. HASH — carried vs content_hash({type, data}) -> hash_mismatch.
# Structural admission is not semantic validation: `data` is never checked against
# the type named by `type`.
#
# NOTE the varint loop reads the continuation bit as a VALUE TEST (andi t1, .., 0x80)
# rather than off a condition-flags register: RISC-V has none, and the standing rule
# is that a rule expressed in terms of a CPU flag must be restated as a value
# comparison before porting.
# =====================================================================
	.type admit_put, @function
admit_put:
	addi sp, sp, -80
	sd   ra, 0(sp)
	sd   s1, 8(sp)
	sd   s2, 16(sp)
	sd   s3, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	sd   s6, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	mv   s1, a0                      # entity value ptr
	# step 1a — must be a map.
	mv   a0, s1
	call read_head                   # a0=after, a1=major, a2=arg
	li   t0, 5
	bne  a1, t0, .Lap_invreq
	# step 1b — non-empty text `type`.
	mv   a0, s1
	lla  a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Lap_invreq
	call read_head
	li   t0, 3
	bne  a1, t0, .Lap_invreq
	beqz a2, .Lap_invreq
	mv   s2, a0                      # type bytes ptr
	mv   s3, a2                      # type len
	# step 1c — `data` PRESENT. Presence, not truthiness: a CBOR null is a legal
	# payload and map_find reports it found, which is the test §6.3 wants.
	mv   a0, s1
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lap_invreq
	mv   s4, a0                      # data value ptr
	call skip_value
	sub  s5, a0, s4                  # data len
	# step 1d — `content_hash` present and a byte string.
	mv   a0, s1
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lap_invreq
	call read_head
	li   t0, 2
	bne  a1, t0, .Lap_invreq
	beqz a2, .Lap_invreq
	mv   s6, a0                      # carried bytes ptr
	mv   s7, a2                      # carried len
	# leading multicodec LEB128 format-code varint (§7.3).
	li   s8, 0                       # fmt
	li   t3, 0                       # shift
	li   t4, 0                       # i
	li   t5, 0                       # done
.Lap_vd:
	bgeu t4, s7, .Lap_vdend
	add  t6, s6, t4
	lbu  t1, 0(t6)
	andi t2, t1, 0x7f
	sll  t2, t2, t3
	or   s8, s8, t2
	addi t4, t4, 1
	andi t6, t1, 0x80
	beqz t6, .Lap_vdone
	addi t3, t3, 7
	li   t6, 64
	bgeu t3, t6, .Lap_vdend
	j    .Lap_vd
.Lap_vdone:
	li   t5, 1
.Lap_vdend:
	beqz t5, .Lap_invreq
	bnez s8, .Lap_unsupfmt           # §1.2 / §4.7 row 5 — shape fine, algorithm absent
	addi t0, t4, 32
	bne  s7, t0, .Lap_invreq
	# step 2 — carried vs content_hash({type, data}).
	mv   a0, s2
	mv   a1, s3
	mv   a2, s4
	mv   a3, s5
	lla  a4, ch_admit
	call ec_content_hash
	# The recompute can FAIL, and its failure is not the submitter's. On any
	# non-EC_OK the C-ABI leaves `out` UNWRITTEN -- ch_admit is .bss holding zeros
	# or the previous admission's digest -- so falling into the memeq below reports
	# hash_mismatch: a codec refusal stated as an accusation about the submitter's
	# bytes. Reachable, and not hypothetically: measured 2026-09-07, the two
	# INTERCHANGEABLE C-ABI impls diverge on 5 of 8 `type` inputs -- the C one
	# hashes a non-UTF-8 `type` and returns EC_OK, the Rust one returns
	# EC_INVALID_ARGUMENT -- and `type` is attacker-controlled wire bytes here
	# (CBOR major 3 does not enforce UTF-8, and step 1b only checks non-empty).
	# A refusal to canonicalize the submission is a step-1 structural fault, so
	# this is invalid_request. There is deliberately no 413 arm as on asm-x86_64:
	# that peer's NATIVE codec has a real EC_OUT_OF_SPACE capacity mode and this
	# one's .so has none. An impl that grows one needs the split.
	bnez a0, .Lap_invreq
	lla  a0, ch_admit
	mv   a1, s6
	li   a2, 33
	call memeq
	beqz a0, .Lap_hashmm
	li   a0, 0
	j    .Lap_done
.Lap_invreq:
	li   a0, 1
	j    .Lap_done
.Lap_unsupfmt:
	li   a0, 2
	j    .Lap_done
.Lap_hashmm:
	li   a0, 3
.Lap_done:
	ld   ra, 0(sp)
	ld   s1, 8(sp)
	ld   s2, 16(sp)
	ld   s3, 24(sp)
	ld   s4, 32(sp)
	ld   s5, 40(sp)
	ld   s6, 48(sp)
	ld   s7, 56(sp)
	ld   s8, 64(sp)
	addi sp, sp, 80
	ret

# serve_tree_put(a0 = exec data map) — §5.2-gated write of params.data.entity at
# resource.targets[0] into the per-fork store; 200 system/tree/put-result{content_hash}.
# s2=exec, s3=path ptr, s4=path len, s5=params.data map, s1=entity blob start.
# =====================================================================
	.type serve_tree_put, @function
serve_tree_put:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s2, a0                     # exec
	mv   a0, s2
	call chain_depth_check
	bnez a0, .Lstp_done
	mv   a0, s2
	call verify_get_auth
	bnez a0, .Lstp_done
	mv   a0, s2
	call verify_get_cap
	bnez a0, .Lstp_done
	mv   a0, s2
	call verify_get_scope
	bnez a0, .Lstp_done
	# path = resource.targets[0]
	mv   a0, s2
	lla  a1, k_resource
	li   a2, 8
	call map_find
	beqz a0, .Lstp_400
	lla  a1, k_targets
	li   a2, 7
	call map_find
	beqz a0, .Lstp_400
	call read_head                   # a2 = count
	beqz a2, .Lstp_400
	call get_text                    # a0=path ptr, a2=path len
	mv   s3, a0
	mv   s4, a2
	# §"invalid_path" reject (dot-relative / empty-segment / NUL) before any write.
	mv   a1, s3
	mv   a3, s4
	call path_valid
	beqz a0, .Lstp_invalid
	# §1.4 canonicalize the store key (peer-relative → /{localPeerID}/…).
	mv   a1, s3
	mv   a3, s4
	call canon_path                  # a0=canon ptr, a2=canon len
	mv   s3, a0
	mv   s4, a2
	# entity = params.data.entity
	mv   a0, s2
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lstp_400
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lstp_400
	mv   s5, a0                     # params.data map
	lla  a1, k_entity
	li   a2, 6
	call map_find
	beqz a0, .Lstp_400
	mv   s1, a0                     # entity blob start (into b_req)
	# CAS pre-check
	mv   a0, s5
	mv   a1, s3
	mv   a2, s4
	call cas_check
	bnez a0, .Lstp_409
	# §6.3 put ADMISSION (0.8.2.11), AFTER the §3.9 CAS gate so a stale precondition
	# stays a 409 whatever was submitted. See admit_put below.
	mv   a0, s1
	call admit_put
	beqz a0, .Lstp_admitted
	li   t0, 2
	beq  a0, t0, .Lstp_unsupfmt
	li   t0, 3
	beq  a0, t0, .Lstp_hashmm
	j    .Lstp_invreq
.Lstp_admitted:
	# blob len = skip_value(entity) - entity
	mv   a0, s1
	call skip_value                  # a0 = entity end
	sub  a0, a0, s1                 # a0 = blob len
	# store_put(path, pathlen, blob, bloblen)
	mv   a3, a0                      # blob len
	mv   a0, s3                      # path ptr
	mv   a1, s4                      # path len
	mv   a2, s1                      # blob ptr
	call store_put
	# put-result content_hash = the stored entity's own content_hash field (§1.8 recompute-equal)
	mv   a0, s1
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lstp_400
	call get_text                    # a0 = chash ptr (33B)
	call send_put_ok
	j    .Lstp_done
.Lstp_409:
	li   a0, 409
	lla  a1, ec_hash_mismatch
	call send_error
	j    .Lstp_done
.Lstp_invreq:
	li   a0, 400
	lla  a1, ec_invalid_request
	call send_error
	j    .Lstp_done
.Lstp_unsupfmt:
	li   a0, 400
	lla  a1, ec_unsupported_chf
	call send_error
	j    .Lstp_done
.Lstp_hashmm:
	li   a0, 400
	lla  a1, ec_hash_mismatch
	call send_error
	j    .Lstp_done
.Lstp_invalid:
	li   a0, 400
	lla  a1, ec_invalid_path
	call send_error
	j    .Lstp_done
.Lstp_400:
	li   a0, 400
	lla  a1, ec_unexpected_params
	call send_error
.Lstp_done:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# send_put_ok(a0 = 33-byte content_hash ptr) — 200 EXECUTE_RESPONSE whose result is a
# freshly-built system/tree/put-result{content_hash} entity. Mirrors send_error's envelope.
# s2=chash ptr, s3=prd data len, s4=resp data len; cursor is s6 (aarch64 x24).
	.type send_put_ok, @function
send_put_ok:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s2, 16(sp)
	sd   s3, 24(sp)
	sd   s4, 32(sp)
	sd   s6, 40(sp)
	mv   s0, sp
	mv   s2, a0                     # chash ptr (33B)
	# ---- put-result inner data {content_hash:<33B>} ----
	lla  s6, b_prd_data
	li   a1, 1
	call w_map
	lla  a0, k_chash
	call w_cstr
	mv   a1, s2
	li   a2, 33
	call w_bstr
	lla  t0, b_prd_data
	sub  s3, s6, t0                # s3 = prd data len
	lla  a0, t_put_result
	li   a1, 22
	lla  a2, b_prd_data
	mv   a3, s3
	lla  a4, prd_ch
	call ec_content_hash
	# ---- response data {result:<put-result entity>, status:200, request_id} ----
	lla  s6, b_put_resp
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	lla  a0, t_put_result
	lla  a1, b_prd_data
	mv   a2, s3
	lla  a3, prd_ch
	call w_entity
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_put_resp
	sub  s4, s6, t0                # s4 = resp data len
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_put_resp
	mv   a3, s4
	lla  a4, put_resp_ch
	call ec_content_hash
	# ---- envelope {root:<resp entity>} ----
	lla  s6, b_put_env
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_put_resp
	mv   a2, s4
	lla  a3, put_resp_ch
	call w_entity
	# ---- frame + send ----
	lla  t0, b_put_env
	sub  s4, s6, t0                # s4 = envelope len
	bswap32 t0, s4                 # 4-byte big-endian frame length
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_put_env
	mv   a2, s4
	call write_all
	ld   s6, 40(sp)
	ld   s4, 32(sp)
	ld   s3, 24(sp)
	ld   s2, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# system/handler register / unregister (writes handler entities to the per-fork store).
# =====================================================================

# find_raw(a0=map, a1=key cstr, a2=key len) -> a0 = value ptr|0, a2 = value byte-length.
# Returns the verbatim CBOR span of a map value (head + body), for embedding via w_raw.
# s2 = value ptr (callee-saved across skip_value).
	.type find_raw, @function
find_raw:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s2, 16(sp)
	mv   s0, sp
	call map_find
	beqz a0, .Lfr_none
	mv   s2, a0
	call skip_value                  # a0 = end
	sub  a2, a0, s2                  # value byte-length
	mv   a0, s2
	ld   s2, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret
.Lfr_none:
	li   a0, 0
	li   a2, 0
	ld   s2, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# mk_entity(a0=type cstr, a1=type len, a2=data ptr, a3=data len, a4=chash out buf) ->
# a0 = entity byte-length. Hashes the data, writes the {data,type,content_hash} entity into
# the shared b_ent_scratch (reg_store copies it out immediately after).
# s2=type cstr, s3=type len, s1=data ptr, s4=data len; cursor is s6.
	.type mk_entity, @function
mk_entity:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s6, 48(sp)
	mv   s0, sp
	mv   s2, a0                     # type cstr
	mv   s3, a1                     # type len
	mv   s1, a2                     # data ptr
	mv   s4, a3                     # data len
	lla  t0, g_chbuf
	sd   a4, 0(t0)
	mv   a0, s2
	mv   a1, s3
	mv   a2, s1
	mv   a3, s4
	lla  t0, g_chbuf
	ld   a4, 0(t0)
	call ec_content_hash
	lla  s6, b_ent_scratch
	mv   a0, s2                     # type cstr
	mv   a1, s1                     # data ptr
	mv   a2, s4                     # data len
	lla  t0, g_chbuf
	ld   a3, 0(t0)                  # chash ptr
	call w_entity
	lla  t0, b_ent_scratch
	sub  a0, s6, t0                 # entlen
	ld   s6, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# reg_store(a0=path ptr, a1=path len, a2=blob ptr, a3=blob len) — canonicalize the path
# (§1.4) and store the entity blob under it. s4=blob ptr, s5=blob len.
	.type reg_store, @function
reg_store:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s4, 16(sp)
	sd   s5, 24(sp)
	mv   s0, sp
	mv   s4, a2                     # blob ptr
	mv   s5, a3                     # blob len
	mv   a3, a1                     # path len (canon_path wants rcx→a3)
	mv   a1, a0                     # path ptr (canon_path wants rsi→a1)
	call canon_path                 # a0=canon ptr, a2=canon len
	# store_put(path, pathlen, blob, bloblen)
	mv   a1, a2                     # canon len → pathlen
	# a0 already = canon ptr
	mv   a2, s4                     # blob ptr
	mv   a3, s5                     # blob len
	call store_put
	ld   s5, 24(sp)
	ld   s4, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# pcat(a0=prefix ptr, a1=prefix len, a2=seg ptr, a3=seg len) -> a0=b_hpath ptr, a2=len.
# s1=prefix ptr, s2=prefix len, s3=seg ptr, s4=seg len.
	.type pcat, @function
pcat:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s1, a0                     # prefix ptr
	mv   s2, a1                     # prefix len
	mv   s3, a2                     # seg ptr
	mv   s4, a3                     # seg len
	lla  a0, b_hpath
	mv   a1, s1
	mv   a2, s2
	call mcpy                        # a0 = dst + preflen
	# mcpy(dst, src, len): a0 already = dst cursor
	mv   a1, s3
	mv   a2, s4
	call mcpy
	lla  a0, b_hpath
	add  a2, s2, s4                 # total len
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# hexenc(a0=src 33-byte ptr, a1=dst ptr) — write 66 lowercase hex chars. Leaf.
	.type hexenc, @function
hexenc:
	li   t0, 0                       # index
.Lhx:
	li   t1, 33
	bgeu t0, t1, .Lhx_done
	add  t2, a0, t0
	lbu  t1, 0(t2)                   # byte
	srli t2, t1, 4                   # high nibble
	lla  t3, hexchars
	add  t3, t3, t2
	lbu  t2, 0(t3)
	sb   t2, 0(a1)
	addi a1, a1, 1
	add  t2, a0, t0
	lbu  t1, 0(t2)
	andi t1, t1, 0xf                 # low nibble
	lla  t2, hexchars
	add  t2, t2, t1
	lbu  t1, 0(t2)
	sb   t1, 0(a1)
	addi a1, a1, 1
	addi t0, t0, 1
	j    .Lhx
.Lhx_done:
	ret

# serve_register(a0 = exec data map) — §5.2-gated system/handler register. Writes 4 entities
# to the store (interface, handler, capability token, signature) and returns 200
# system/handler/register-result {grant, pattern}.
# s2=exec, s3=params.data, s4=manifest map; cursor is s6.
	.type serve_register, @function
serve_register:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s6, 48(sp)
	mv   s0, sp
	mv   s2, a0                     # exec
	mv   a0, s2
	call chain_depth_check
	bnez a0, .Lsr_done
	mv   a0, s2
	call verify_get_auth
	bnez a0, .Lsr_done
	mv   a0, s2
	call verify_get_cap
	bnez a0, .Lsr_done
	mv   a0, s2
	call verify_get_scope
	bnez a0, .Lsr_done
	# params.data → s3
	mv   a0, s2
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lsr_400
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lsr_400
	mv   s3, a0                     # params.data
	# manifest → s4
	mv   a0, s3
	lla  a1, k_manifest
	li   a2, 8
	call map_find
	beqz a0, .Lsr_400
	mv   s4, a0                     # manifest map
	# pattern content → g_hpat
	mv   a0, s4
	lla  a1, k_pattern
	li   a2, 7
	call map_find
	beqz a0, .Lsr_400
	call get_text
	lla  t0, g_hpat_ptr
	sd   a0, 0(t0)
	lla  t0, g_hpat_len
	sd   a2, 0(t0)
	# ── §6.2 reserved-pattern guard ─────────────────────────────────────
	# user-installed handlers MUST NOT register at system/* paths. Runs
	# right after the pattern is extracted but BEFORE any of the five
	# normative writes below (interface/handler/token/signature/response).
	# Reserved iff pattern == "system" (len 6, exact) or pattern starts
	# with "system/" (len >= 7, prefix). s1 free in this function.
	lla  t0, g_hpat_len
	ld   s1, 0(t0)                  # pattern len
	li   t0, 7
	blt  s1, t0, .Lsr_pat_chk6
	lla  t0, g_hpat_ptr
	ld   a0, 0(t0)
	lla  a1, p_sys_slash
	li   a2, 7
	call memeq
	bnez a0, .Lsr_reserved
	j    .Lsr_pat_ok
.Lsr_pat_chk6:
	li   t0, 6
	bne  s1, t0, .Lsr_pat_ok
	lla  t0, g_hpat_ptr
	ld   a0, 0(t0)
	lla  a1, p_sys_bare
	li   a2, 6
	call memeq
	beqz a0, .Lsr_pat_ok
.Lsr_reserved:
	li   a0, 403
	lla  a1, ec_forbidden_pattern
	call send_error
	j    .Lsr_done
.Lsr_pat_ok:
	# interface store path = "system/handler/" + pattern → save into b_ipath
	lla  a0, p_hnd_slash
	li   a1, 15
	lla  t0, g_hpat_ptr
	ld   a2, 0(t0)
	lla  t0, g_hpat_len
	ld   a3, 0(t0)
	call pcat                        # a0=b_hpath, a2=len
	lla  t0, g_ipath_len
	sd   a2, 0(t0)
	mv   a1, a0                      # src = b_hpath
	lla  a0, b_ipath                 # dst
	# a2 already = len
	call mcpy

	# ===== 1. interface entity {name, pattern, operations} =====
	lla  s6, b_iface_data
	li   a1, 3
	call w_map
	lla  a0, k_name
	call w_cstr
	mv   a0, s4
	lla  a1, k_name
	li   a2, 4
	call find_raw                    # a0=ptr, a2=len
	mv   a1, a0
	call w_raw
	lla  a0, k_pattern
	call w_cstr
	mv   a0, s4
	lla  a1, k_pattern
	li   a2, 7
	call find_raw
	mv   a1, a0
	call w_raw
	lla  a0, ka_operations
	call w_cstr
	mv   a0, s4
	lla  a1, ka_operations
	li   a2, 10
	call find_raw
	mv   a1, a0
	call w_raw
	lla  t0, b_iface_data
	sub  a3, s6, t0
	lla  t0, g_tmplen
	sd   a3, 0(t0)
	lla  a0, t_iface
	li   a1, 24
	lla  a2, b_iface_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, iface_ch
	call mk_entity                   # a0 = entlen; blob in b_ent_scratch
	# store at b_ipath
	mv   a3, a0                      # blob len
	lla  a0, b_ipath                 # path ptr
	lla  t0, g_ipath_len
	ld   a1, 0(t0)                   # path len
	lla  a2, b_ent_scratch           # blob ptr
	call reg_store

	# ===== 2. handler entity {interface, internal_scope, expression_path} =====
	lla  s6, b_hdlr_data
	li   a1, 3
	call w_map
	lla  a0, k_interface
	call w_cstr
	lla  a1, b_ipath
	lla  t0, g_ipath_len
	ld   a2, 0(t0)
	call w_txt
	lla  a0, k_internal_scope
	call w_cstr
	mv   a0, s4
	lla  a1, k_internal_scope
	li   a2, 14
	call find_raw
	mv   a1, a0
	call w_raw
	lla  a0, k_expr_path
	call w_cstr
	mv   a0, s4
	lla  a1, k_expr_path
	li   a2, 15
	call find_raw
	mv   a1, a0
	call w_raw
	lla  t0, b_hdlr_data
	sub  a3, s6, t0
	lla  t0, g_tmplen
	sd   a3, 0(t0)
	lla  a0, t_handler
	li   a1, 14
	lla  a2, b_hdlr_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, hdlr_ch
	call mk_entity
	mv   a3, a0                      # blob len
	lla  t0, g_hpat_ptr
	ld   a0, 0(t0)                   # path ptr
	lla  t0, g_hpat_len
	ld   a1, 0(t0)                   # path len
	lla  a2, b_ent_scratch           # blob ptr
	call reg_store

	# ===== 3. capability token {grants, grantee, granter, created_at} =====
	call now_ms
	lla  t0, g_created
	sd   a0, 0(t0)
	lla  s6, b_htok_data
	li   a1, 4
	call w_map
	lla  a0, ka_grants
	call w_cstr
	mv   a0, s3
	lla  a1, k_req_scope
	li   a2, 15
	call find_raw
	mv   a1, a0
	call w_raw
	lla  a0, ka_grantee
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_granter
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_created
	call w_cstr
	lla  t0, g_created
	ld   a1, 0(t0)
	call w_uint
	lla  t0, b_htok_data
	sub  a3, s6, t0
	lla  t0, g_htoklen
	sd   a3, 0(t0)
	lla  a0, ta_token
	li   a1, 23
	lla  a2, b_htok_data
	lla  t0, g_htoklen
	ld   a3, 0(t0)
	lla  a4, htok_ch
	call mk_entity
	# token store path = "system/capability/grants/" + pattern
	mv   s5, a0                      # entlen (survives pcat)
	lla  a0, p_cap_grants
	li   a1, 25
	lla  t0, g_hpat_ptr
	ld   a2, 0(t0)
	lla  t0, g_hpat_len
	ld   a3, 0(t0)
	call pcat                        # a0=b_hpath, a2=len
	mv   a1, a2                      # path len
	# a0 already = b_hpath (path ptr)
	lla  a2, b_ent_scratch           # blob ptr
	mv   a3, s5                      # blob len
	call reg_store

	# ===== 4. signature {signer, target, algorithm, signature} over the token hash =====
	lla  a0, g_seed
	lla  a1, htok_ch
	li   a2, 33
	lla  a3, htok_sig
	call ec_ed25519_sign
	lla  s6, b_hsig_data
	li   a1, 4
	call w_map
	lla  a0, ka_signer
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_target
	call w_cstr
	lla  a1, htok_ch
	li   a2, 33
	call w_bstr
	lla  a0, ka_algo
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_sig
	call w_cstr
	lla  a1, htok_sig
	li   a2, 64
	call w_bstr
	lla  t0, b_hsig_data
	sub  a3, s6, t0
	lla  t0, g_tmplen
	sd   a3, 0(t0)
	lla  a0, ta_sig
	li   a1, 16
	lla  a2, b_hsig_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, hsig_ch
	call mk_entity
	# sig store path = "system/signature/" + hex(htok_ch)
	mv   s5, a0                      # entlen
	lla  a0, htok_ch
	lla  a1, b_hex
	call hexenc
	lla  a0, p_sig_slash
	li   a1, 17
	lla  a2, b_hex
	li   a3, 66
	call pcat
	mv   a1, a2                      # path len
	# a0 already = b_hpath (path ptr)
	lla  a2, b_ent_scratch           # blob ptr
	mv   a3, s5                      # blob len
	call reg_store

	# ===== register-result {grant:<token data>, pattern} =====
	lla  s6, b_regres_data
	li   a1, 2
	call w_map
	lla  a0, k_grant
	call w_cstr
	lla  a1, b_htok_data
	lla  t0, g_htoklen
	ld   a2, 0(t0)
	call w_raw
	lla  a0, k_pattern
	call w_cstr
	lla  t0, g_hpat_ptr
	ld   a1, 0(t0)
	lla  t0, g_hpat_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_regres_data
	sub  a3, s6, t0
	lla  t0, g_tmplen
	sd   a3, 0(t0)
	lla  a0, t_reg_result
	li   a1, 30
	lla  a2, b_regres_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, regres_ch
	call mk_entity                   # entity → b_ent_scratch
	# wrap as the response result via send_get_ok
	mv   a1, a0                      # entlen
	lla  a0, b_ent_scratch
	call send_get_ok
	j    .Lsr_done
.Lsr_400:
	li   a0, 400
	lla  a1, ec_unexpected_params
	call send_error
.Lsr_done:
	ld   s6, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# serve_unregister(a0 = exec data map) — remove the handler entities for the pattern named by
# resource.targets[0] (= system/handler/<pattern>). Deletes interface, handler, token and the
# invariant-path signature, then returns 200 with a null result entity.
# s2=exec, s3=target ptr, s4=target len, s5=pattern ptr, s1=pattern len; cursor s6.
	.type serve_unregister, @function
serve_unregister:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)
	mv   s0, sp
	mv   s2, a0                     # exec
	mv   a0, s2
	call verify_get_auth
	bnez a0, .Lsu_done
	mv   a0, s2
	call verify_get_cap
	bnez a0, .Lsu_done
	mv   a0, s2
	call verify_get_scope
	bnez a0, .Lsu_done
	# target = resource.targets[0]  (= system/handler/<pattern>)
	mv   a0, s2
	lla  a1, k_resource
	li   a2, 8
	call map_find
	beqz a0, .Lsu_ok
	lla  a1, k_targets
	li   a2, 7
	call map_find
	beqz a0, .Lsu_ok
	call read_head
	beqz a2, .Lsu_ok
	call get_text                    # a0=target ptr, a2=target len (= interface path)
	mv   s3, a0                     # target ptr
	mv   s4, a2                     # target len
	# pattern = target after the "system/handler/" (15-byte) prefix
	addi s5, s3, 15                 # pattern ptr
	addi s1, s4, -15                # pattern len
	# token path = "system/capability/grants/" + pattern → look it up for its content_hash
	lla  a0, p_cap_grants
	li   a1, 25
	mv   a2, s5
	mv   a3, s1
	call pcat                        # a0=b_hpath, a2=len
	mv   a1, a0                      # path ptr (canon_path wants rsi→a1)
	mv   a3, a2                      # path len (canon_path wants rcx→a3)
	call canon_path                  # a0=canon, a2=len
	mv   a1, a0                      # path ptr (store_get wants rsi→a1)
	mv   a3, a2                      # path len (store_get wants rcx→a3)
	call store_get                   # a0=token blob|0
	beqz a0, .Lsu_delrest
	# recompute sig path from the token's content_hash field → delete it
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lsu_delrest
	call get_text                    # a0 = 33-byte token hash ptr
	lla  a1, b_hex
	call hexenc
	lla  a0, p_sig_slash
	li   a1, 17
	lla  a2, b_hex
	li   a3, 66
	call pcat
	mv   a1, a2                      # path len (store_delete wants rsi→a1)
	# a0 already = b_hpath (path ptr)
	call store_delete
.Lsu_delrest:
	# delete interface (= target), handler (= pattern), token (= grants path)
	mv   a0, s3
	mv   a1, s4
	call store_delete
	mv   a0, s5
	mv   a1, s1
	call store_delete
	lla  a0, p_cap_grants
	li   a1, 25
	mv   a2, s5
	mv   a3, s1
	call pcat
	mv   a1, a2                      # path len
	# a0 already = b_hpath (path ptr)
	call store_delete
.Lsu_ok:
	# 200 with a null result entity {data:null, type:"", content_hash:<33 zero>}
	lla  s6, b_regres_env
	li   a1, 3
	call w_map
	lla  a0, k_data
	call w_cstr
	li   t0, 0xf6                   # null
	sb   t0, 0(s6)
	addi s6, s6, 1
	lla  a0, k_type
	call w_cstr
	li   t0, 0x60                   # empty text ""
	sb   t0, 0(s6)
	addi s6, s6, 1
	lla  a0, k_chash
	call w_cstr
	lla  a1, b_zero33
	li   a2, 33
	call w_bstr
	lla  t0, b_regres_env
	sub  a1, s6, t0                 # entity len
	lla  a0, b_regres_env
	call send_get_ok
.Lsu_done:
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret
	.type serve_configure, @function
serve_configure:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s1, a0                     # exec (was r12)
	mv   a0, s1
	call verify_get_auth
	bnez a0, .Lsc_done
	mv   a0, s1
	call verify_get_cap
	bnez a0, .Lsc_done
	# NB: no verify_get_scope — a configure request carries no resource.targets (the peer
	# policy names its scope via params.data.grants), so the target-based scope gate does not
	# apply; auth + capability presence is the gate.
	# params entity (raw span) → s2 ptr, s3 len (echoed + stored).
	mv   a0, s1
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lsc_400
	mv   s2, a0                     # params entity start
	call skip_value
	sub  s3, a0, s2                # params entity len
	# peer_pattern = params.data.peer_pattern
	mv   a0, s2
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lsc_400
	lla  a1, k_peer_pattern
	li   a2, 12
	call map_find
	beqz a0, .Lsc_store              # no peer_pattern → nothing to validate/index
	call get_text                    # a0=pat ptr, a2=pat len
	mv   s4, a0                     # pattern ptr (was r15)
	mv   s5, a2                     # pattern len (was rbx)
	# §V7 §4 reject a partial-prefix wildcard peer_pattern (any '*') → 400 invalid_params.
	li   t0, 0
.Lsc_wc:
	bgeu t0, s5, .Lsc_wc_ok
	add  t1, s4, t0
	lbu  t1, 0(t1)                 # '*'
	li   t2, 0x2a
	beq  t1, t2, .Lsc_invalid
	addi t0, t0, 1
	j    .Lsc_wc
.Lsc_wc_ok:
	# store the policy-entry at system/capability/policy/<peer_pattern>
	lla  a0, p_cap_policy
	li   a1, 25
	mv   a2, s4
	mv   a3, s5
	call pcat                        # a0=b_hpath, a2=len
	mv   a1, a2                      # len
	# a0 already = path ptr
	mv   a2, s2                     # params entity ptr
	mv   a3, s3                     # params entity len
	call reg_store
.Lsc_store:
	# echo the params policy-entry entity verbatim as the 200 result
	mv   a0, s2
	mv   a1, s3
	call send_get_ok
	j    .Lsc_done
.Lsc_invalid:
	li   a0, 400
	lla  a1, ec_invalid_params
	call send_error
	j    .Lsc_done
.Lsc_400:
	li   a0, 400
	lla  a1, ec_unexpected_params
	call send_error
.Lsc_done:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# serve_delegate(a0 = exec) — §6.9a delegate. v1 is same-peer-only; a request with a parent
# field is unsupported (501, construct the attenuated child client-side); one lacking the
# required parent field is malformed (400 invalid_params).
	.type serve_delegate, @function
serve_delegate:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	# a0 = exec (no callee-saved needed — value not held across a call)
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lsdl2_501
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lsdl2_501
	lla  a1, ka_parent
	li   a2, 6
	call map_find
	beqz a0, .Lsdl2_noparent
.Lsdl2_501:
	li   a0, 501
	lla  a1, ec_unsupported_op
	call send_error
	j    .Lsdl2_done
.Lsdl2_noparent:
	li   a0, 400
	lla  a1, ec_invalid_params
	call send_error
.Lsdl2_done:
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# serve_revoke(a0 = exec) — §6.9a revoke. Writes a system/capability/revocation marker at
# system/capability/revocations/<hex(token)> and returns 200 with the revocation entity. A
# zero token is rejected (400 invalid_params).
	.type serve_revoke, @function
serve_revoke:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)                 # save s6 (global cursor) — this fn sets it up
	mv   s0, sp
	mv   s1, a0                     # exec (was r12)
	mv   a0, s1
	call verify_get_auth
	bnez a0, .Lrv_done
	mv   a0, s1
	call verify_get_cap
	bnez a0, .Lrv_done
	mv   a0, s1
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lrv_400
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lrv_400
	mv   s2, a0                     # params.data (was r13)
	# token (33B) → s3 (was r14)
	lla  a1, ka_token
	li   a2, 5
	call map_find
	beqz a0, .Lrv_400
	call get_text                    # a0=token ptr, a2=len
	li   t0, 33
	bne  a2, t0, .Lrv_400
	mv   s3, a0                     # token ptr
	# reject an all-zero token
	li   t0, 0                      # index
	li   t1, 0                      # OR accumulator
.Lrv_zscan:
	li   t2, 33
	bgeu t0, t2, .Lrv_zdone
	add  t2, s3, t0
	lbu  t2, 0(t2)
	or   t1, t1, t2
	addi t0, t0, 1
	j    .Lrv_zscan
.Lrv_zdone:
	beqz t1, .Lrv_invalid           # all-zero token
	call now_ms
	lla  t0, g_created
	sd   a0, 0(t0)
	# reason (verbatim) if present
	mv   a0, s2
	lla  a1, k_reason
	li   a2, 6
	call find_raw                    # a0=value ptr|0, a2=value len
	mv   s4, a0                     # reason value ptr (0 if absent) (was rbx)
	lla  t0, g_tmplen
	sd   a2, 0(t0)                   # reason len
	# ---- revocation data ----
	lla  s5, b_revoke_data          # cursor tracker (was r15); s6 = write cursor
	mv   s6, s5
	beqz s4, .Lrv_map2
	li   a1, 3
	call w_map
	j    .Lrv_tok
.Lrv_map2:
	li   a1, 2
	call w_map
.Lrv_tok:
	lla  a0, ka_token
	call w_cstr
	mv   a1, s3                     # token ptr
	li   a2, 33
	call w_bstr
	beqz s4, .Lrv_revat
	lla  a0, k_reason
	call w_cstr
	mv   a1, s4                     # reason ptr
	lla  t0, g_tmplen
	ld   a2, 0(t0)                   # reason len
	call w_raw
.Lrv_revat:
	lla  a0, k_revoked_at
	call w_cstr
	lla  t0, g_created
	ld   a1, 0(t0)
	call w_uint
	lla  t0, b_revoke_data
	sub  t0, s6, t0                 # data len
	lla  t1, g_tmplen
	sd   t0, 0(t1)
	lla  a0, t_revocation
	li   a1, 28
	lla  a2, b_revoke_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, revoke_ch
	call mk_entity                   # a0=entlen; entity in b_ent_scratch
	mv   s5, a0                     # entlen (was r15)
	# store at system/capability/revocations/<hex(token)>
	mv   a0, s3                     # token ptr
	lla  a1, b_hex
	call hexenc
	lla  a0, p_cap_revoke
	li   a1, 30
	lla  a2, b_hex
	li   a3, 66
	call pcat                        # a0=path ptr, a2=len
	mv   a1, a2                      # len
	lla  a2, b_ent_scratch
	mv   a3, s5                     # entlen
	call reg_store
	# 200 result = the revocation entity
	lla  a0, b_ent_scratch
	mv   a1, s5                     # entlen
	call send_get_ok
	j    .Lrv_done
.Lrv_invalid:
	li   a0, 400
	lla  a1, ec_invalid_params
	call send_error
	j    .Lrv_done
.Lrv_400:
	li   a0, 400
	lla  a1, ec_unexpected_params
	call send_error
.Lrv_done:
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# is_revoked(a0 = 33-byte token hash) -> a0 = 1 if a revocation marker exists in the store.
	.type is_revoked, @function
is_revoked:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	# a0 = token ptr (not held across a call after hexenc consumes it)
	lla  a1, b_hex
	call hexenc
	lla  a0, p_cap_revoke
	li   a1, 30
	lla  a2, b_hex
	li   a3, 66
	call pcat                        # a0=b_hpath, a2=len
	mv   a1, a0                      # path ptr → a1
	mv   a3, a2                      # path len → a3 (canon_path wants a3)
	call canon_path                  # a0=canon, a2=len
	mv   a1, a0                      # canon → a1
	mv   a3, a2                      # canon len → a3 (store_get wants a3)
	call store_get                   # a0=blob|0
	snez a0, a0                      # setnz + movzbl → 0/1
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# seed_one(a0=pattern ptr, a1=pattern len, a2=interface ptr, a3=interface len) — publish a
# §6.2 native dispatch entity  {interface:<interface>}  (type system/handler, no expression_path
# ⇒ dispatch_type native) at the bare pattern path.
	.type seed_one, @function
seed_one:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)                  # save s6 (global cursor)
	mv   s0, sp
	mv   s1, a0                      # pattern ptr (was r12)
	mv   s2, a1                      # pattern len (was r13)
	mv   s3, a2                      # interface ptr (was rbx)
	mv   s4, a3                      # interface len (was r14)
	lla  s5, b_hdlr_data             # cursor tracker (was r15)
	mv   s6, s5
	li   a1, 1
	call w_map
	lla  a0, k_interface
	call w_cstr
	mv   a1, s3                      # interface ptr
	mv   a2, s4                      # interface len
	call w_txt
	lla  t0, b_hdlr_data
	sub  t0, s6, t0
	lla  t1, g_tmplen
	sd   t0, 0(t1)
	lla  a0, t_handler
	li   a1, 14
	lla  a2, b_hdlr_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, hdlr_ch
	call mk_entity                   # a0 = entlen
	mv   a3, a0                      # entlen → reg_store arg 4
	mv   a0, s1                      # pattern ptr
	mv   a1, s2                      # pattern len
	lla  a2, b_ent_scratch
	call reg_store
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# seed_dispatch_entities — publish the built-in native dispatch entities (§6.2 N2/N5) into the
# per-fork store so a get at system/{tree,protocol/connect,capability} resolves a system/handler
# entity with an `interface` ref. Called once per connection (per fork).
	.type seed_dispatch_entities, @function
seed_dispatch_entities:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	lla  a0, va_systree
	li   a1, 11
	lla  a2, s_iface_tree
	li   a3, 26
	call seed_one
	lla  a0, s_pat_connect
	li   a1, 23
	lla  a2, s_iface_connect
	li   a3, 38
	call seed_one
	lla  a0, va_syscap
	li   a1, 17
	lla  a2, s_iface_cap
	li   a3, 32
	call seed_one
	# §7a validate scaffold — publishing system/handler/system/validate/dispatch-outbound is
	# the oracle's --validate gate for BOTH validate_echo_dispatch and t1_2_concurrent_reentry.
	lla  a0, s_name_echo
	lla  a1, s_pat_echo
	lla  a2, va_echo
	lla  a3, s_iface_echo
	call seed_vh
	lla  a0, s_name_dout
	lla  a1, s_pat_dout
	lla  a2, va_dispatch
	lla  a3, s_iface_dout
	call seed_vh
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# seed_vh(a0=name cstr, a1=pattern cstr, a2=op cstr, a3=interface cstr) — publish a
# validate handler: interface {name,pattern,operations:{op:{input_type,output_type}}} at the
# interface path + a native dispatch entity at the pattern path. Lengths via strlen.
	.type seed_vh, @function
seed_vh:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)                  # save s6 (global cursor)
	mv   s0, sp
	mv   s1, a0                      # name (was r12)
	mv   s2, a1                      # pattern (was r13)
	mv   s3, a2                      # op (was rbx)
	mv   s4, a3                      # interface (was r14)
	lla  s5, b_iface_data            # cursor tracker (was r15)
	mv   s6, s5
	li   a1, 3
	call w_map
	lla  a0, k_name
	call w_cstr
	mv   a0, s1                      # name
	call w_cstr
	lla  a0, k_pattern
	call w_cstr
	mv   a0, s2                      # pattern
	call w_cstr
	lla  a0, ka_operations
	call w_cstr
	li   a1, 1
	call w_map
	mv   a0, s3                      # op key
	call w_cstr
	li   a1, 2
	call w_map
	lla  a0, k_input_type
	call w_cstr
	lla  a0, v_prim_any
	call w_cstr
	lla  a0, k_output_type
	call w_cstr
	lla  a0, v_prim_any
	call w_cstr
	lla  t0, b_iface_data
	sub  t0, s6, t0
	lla  t1, g_tmplen
	sd   t0, 0(t1)
	lla  a0, t_iface
	li   a1, 24
	lla  a2, b_iface_data
	lla  t0, g_tmplen
	ld   a3, 0(t0)
	lla  a4, iface_ch
	call mk_entity
	mv   s5, a0                      # entlen (was r15)
	mv   a0, s4                      # interface
	call strlen                      # a0 = interface len
	mv   a1, a0                      # interface len → a1
	mv   a0, s4                      # interface ptr → a0
	lla  a2, b_ent_scratch
	mv   a3, s5                      # entlen
	call reg_store
	# native dispatch entity at the pattern path
	mv   a0, s2                      # pattern
	call strlen                      # a0 = pattern len
	mv   s1, a0                      # pattern len (was r12; name no longer needed)
	mv   a0, s4                      # interface
	call strlen                      # a0 = interface len
	mv   a3, a0                      # ifacelen (seed_one arg 4)
	mv   a0, s2                      # pattern ptr
	mv   a1, s1                      # pattern len
	mv   a2, s4                      # interface ptr
	call seed_one
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# gen_erid — build a unique outbound-echo request_id "e<hex>" into b_erid (len → g_erid_len).
	.type gen_erid, @function
gen_erid:
	lla  t0, echo_ctr
	ld   a0, 0(t0)
	lla  a1, b_erid
	li   t0, 0x65                    # 'e'
	sb   t0, 0(a1)
	srli a2, a0, 4
	andi a2, a2, 0xf
	lla  a3, hexchars
	add  t0, a3, a2
	lbu  a2, 0(t0)
	sb   a2, 1(a1)
	andi a2, a0, 0xf
	lla  a3, hexchars
	add  t0, a3, a2
	lbu  a2, 0(t0)
	sb   a2, 2(a1)
	lla  t0, g_erid_len
	li   t1, 3
	sd   t1, 0(t0)
	lla  t0, echo_ctr
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
	ret

# fill_incl(a0=incl entry ptr, a1=parent map, a2=key cstr, a3=key len, a4=type cstr) —
# populate a 40-byte emit_sorted_included entry from a parent[key] sub-entity:
# [0]=chash(key) [8]=type [16]=data ptr [24]=data len [32]=chash.
	.type fill_incl, @function
fill_incl:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a0                      # entry (was r12)
	mv   s3, a4                      # type cstr (was r14)
	mv   a0, a1                      # parent → a0
	mv   a1, a2                      # key → a1
	mv   a2, a3                      # keylen → a2
	call map_find                    # a0 = entity map
	beqz a0, .Lfi_ret
	mv   s2, a0                      # entity (was r13)
	# content_hash
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lfi_ret
	call get_text                    # a0 = chash ptr
	sd   a0, 0(s1)                   # [0]
	sd   a0, 32(s1)                  # [32]
	sd   s3, 8(s1)                   # [8] type
	# data span
	mv   a0, s2                      # entity
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lfi_ret
	sd   a0, 16(s1)                  # [16] data ptr
	call skip_value
	ld   t0, 16(s1)
	sub  a0, a0, t0                  # data len
	sd   a0, 24(s1)                  # [24]
.Lfi_ret:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# serve_dispatch_outbound(a0 = exec) — §7a.2a: originate a reentry echo EXECUTE to the target
# peer (the validator, same socket) using the handed-in reentry_capability, and record the
# pending dispatch so its response is emitted when the echo reply arrives (handle_dispatch_response).
	.type serve_dispatch_outbound, @function
serve_dispatch_outbound:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)                  # save s6 (global cursor)
	mv   s0, sp
	mv   s1, a0                      # exec (was r12)
	# pd = exec.params.data → s2 (was r13)
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lsdo_ret
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lsdo_ret
	mv   s2, a0                      # pd
	# target text
	lla  a1, k_target
	li   a2, 6
	call map_find
	beqz a0, .Lsdo_ret
	call get_text                    # a0=ptr, a2=len
	lla  t0, g_dtarget_ptr
	sd   a0, 0(t0)
	lla  t0, g_dtarget_len
	sd   a2, 0(t0)
	# rcap_hash = reentry_capability.content_hash
	mv   a0, s2
	lla  a1, k_reentry_capability
	li   a2, 18
	call map_find
	beqz a0, .Lsdo_ret
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lsdo_ret
	call get_text
	lla  t0, g_rcap_hash
	sd   a0, 0(t0)
	# ---- echo params entity {data:<value map>, type:primitive/any, content_hash} ----
	mv   a0, s2
	lla  a1, k_value
	li   a2, 5
	call find_raw                    # a0=value map ptr, a2=len
	lla  t0, g_dvalue_ptr
	sd   a0, 0(t0)
	lla  t0, g_dvalue_len
	sd   a2, 0(t0)
	lla  a0, t_prim_any
	li   a1, 13
	lla  t0, g_dvalue_ptr
	ld   a2, 0(t0)
	lla  t0, g_dvalue_len
	ld   a3, 0(t0)
	lla  a4, eparams_ch
	call ec_content_hash
	lla  s5, b_eparams               # cursor tracker (was r15)
	mv   s6, s5
	lla  a0, t_prim_any
	lla  t0, g_dvalue_ptr
	ld   a1, 0(t0)
	lla  t0, g_dvalue_len
	ld   a2, 0(t0)
	lla  a3, eparams_ch
	call w_entity                    # echo params entity → b_eparams
	lla  t0, b_eparams
	sub  a2, s6, t0
	lla  t0, g_eplen
	sd   a2, 0(t0)                   # echo params entity len
	# ---- EXECUTE data {uri, author, params, operation, capability, request_id} ----
	call gen_erid
	lla  s5, b_edata                 # cursor tracker (was r15)
	mv   s6, s5
	li   a1, 6
	call w_map
	lla  a0, k_uri
	call w_cstr
	lla  t0, g_dtarget_ptr
	ld   a1, 0(t0)
	lla  t0, g_dtarget_len
	ld   a2, 0(t0)
	call w_txt
	lla  a0, k_author
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_params
	call w_cstr
	lla  a1, b_eparams
	lla  t0, g_eplen
	ld   a2, 0(t0)
	call w_raw
	lla  a0, k_op
	call w_cstr
	lla  a0, va_echo
	call w_cstr
	lla  a0, k_capability
	call w_cstr
	lla  t0, g_rcap_hash
	ld   a1, 0(t0)
	li   a2, 33
	call w_bstr
	lla  a0, k_rid
	call w_cstr
	lla  a1, b_erid
	lla  t0, g_erid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_edata
	sub  a2, s6, t0
	lla  t0, g_edlen
	sd   a2, 0(t0)
	# ch(execute data)
	lla  a0, t_execute
	li   a1, 23
	lla  a2, b_edata
	lla  t0, g_edlen
	ld   a3, 0(t0)
	lla  a4, edata_ch
	call ec_content_hash
	# ---- our PoP signature over the EXECUTE hash ----
	lla  a0, g_seed
	lla  a1, edata_ch
	li   a2, 33
	lla  a3, esig_bytes
	call ec_ed25519_sign
	lla  s5, b_esig                  # cursor tracker (was r15)
	mv   s6, s5
	li   a1, 4
	call w_map
	lla  a0, ka_signer
	call w_cstr
	lla  a1, g_identity_hash
	li   a2, 33
	call w_bstr
	lla  a0, ka_target
	call w_cstr
	lla  a1, edata_ch
	li   a2, 33
	call w_bstr
	lla  a0, ka_algo
	call w_cstr
	lla  a0, v_ed25519
	call w_cstr
	lla  a0, ka_sig
	call w_cstr
	lla  a1, esig_bytes
	li   a2, 64
	call w_bstr
	lla  t0, b_esig
	sub  s4, s6, t0                  # esig data len (was r14)
	lla  a0, ta_sig
	li   a1, 16
	lla  a2, b_esig
	mv   a3, s4
	lla  a4, esig_ch
	call ec_content_hash
	# ---- included table: 5 entries ----
	lla  s3, do_incl_tab             # table base (was rbx)
	# entry 0: our peer
	lla  t0, g_identity_hash
	sd   t0, 0(s3)
	lla  t0, ta_peer
	sd   t0, 8(s3)
	lla  t0, b_peerdata
	sd   t0, 16(s3)
	lla  t0, g_peerdata_len
	ld   t0, 0(t0)
	sd   t0, 24(s3)
	lla  t0, g_identity_hash
	sd   t0, 32(s3)
	# entry 1: our PoP signature
	lla  t0, esig_ch
	sd   t0, 40(s3)
	lla  t0, ta_sig
	sd   t0, 48(s3)
	lla  t0, b_esig
	sd   t0, 56(s3)
	sd   s4, 64(s3)
	lla  t0, esig_ch
	sd   t0, 72(s3)
	# entry 2: reentry_capability
	addi a0, s3, 80
	mv   a1, s2
	lla  a2, k_reentry_capability
	li   a3, 18
	lla  a4, ta_token
	call fill_incl
	# entry 3: reentry_granter (granter peer)
	addi a0, s3, 120
	mv   a1, s2
	lla  a2, k_reentry_granter
	li   a3, 15
	lla  a4, ta_peer
	call fill_incl
	# entry 4: reentry_cap_signature
	addi a0, s3, 160
	mv   a1, s2
	lla  a2, k_reentry_cap_signature
	li   a3, 21
	lla  a4, ta_sig
	call fill_incl
	# ---- envelope {root:<EXECUTE entity>, included} ----
	lla  s5, b_do_env                # cursor tracker (was r15)
	mv   s6, s5
	li   a1, 2
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_execute
	lla  a1, b_edata
	lla  t0, g_edlen
	ld   a2, 0(t0)
	lla  a3, edata_ch
	call w_entity
	lla  a0, ka_included
	call w_cstr
	li   a0, 5
	lla  a1, do_incl_tab
	call emit_sorted_included
	# ---- frame + send to the validator (as B) on this connection ----
	lla  t0, b_do_env
	sub  s4, s6, t0                  # envelope len (was r14)
	bswap32 t0, s4
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_do_env
	mv   a2, s4
	call write_all
	# ---- record pending {echo_rid → dispatch request_id} ----
	lla  t0, pending_n
	ld   a0, 0(t0)
	li   t0, 16
	bgeu a0, t0, .Lsdo_ret           # table full — drop
	li   t0, 80
	mul  t0, a0, t0
	lla  s3, pending_tab             # table base (was rbx)
	add  s3, s3, t0                  # entry
	# copy echo_rid
	mv   a0, s3                      # dst
	lla  a1, b_erid                  # src
	lla  t0, g_erid_len
	ld   a2, 0(t0)
	call mcpy
	lla  t0, g_erid_len
	ld   t0, 0(t0)
	sd   t0, 32(s3)
	# copy dispatch request_id (g_rid)
	addi a0, s3, 40                  # dst
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)                   # src
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call mcpy
	lla  t0, g_rid_len
	ld   t0, 0(t0)
	sd   t0, 72(s3)
	lla  t0, pending_n
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
.Lsdo_ret:
	ld   s6, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# handle_dispatch_response(a0 = response root.data map = {result, status, request_id}) —
# match the echo reply's request_id to a pending dispatch-outbound and emit its 200 response
# {result:{type:primitive/any, data:{result:<echo result>, status:<echo status>}}, status:200}.
	.type handle_dispatch_response, @function
handle_dispatch_response:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s6, 64(sp)                  # save s6 (global cursor)
	mv   s0, sp
	mv   s1, a0                      # response data (was r12)
	# request_id → find pending entry
	lla  a1, k_rid
	li   a2, 10
	call map_find
	beqz a0, .Lhdr_ret
	call get_text                    # a0=erid ptr, a2=erid len
	mv   s2, a0                      # erid ptr (was r13)
	mv   s3, a2                      # erid len (was r14)
	lla  s4, pending_tab             # table base (was rbx)
	lla  t0, pending_n
	ld   s5, 0(t0)                   # pending_n (was r15)
	li   s7, 0                       # scan index (was r10)
.Lhdr_scan:
	bgeu s7, s5, .Lhdr_ret           # no match (unknown response)
	li   t0, 80
	mul  t0, s7, t0
	lla  s4, pending_tab
	add  s4, s4, t0                  # entry
	ld   t0, 32(s4)                  # entry.erid_len
	bne  t0, s3, .Lhdr_next
	mv   a0, s4
	mv   a1, s2
	mv   a2, s3                      # len → memeq a2
	call memeq
	bnez a0, .Lhdr_found
.Lhdr_next:
	addi s7, s7, 1
	j    .Lhdr_scan
.Lhdr_found:
	# save the dispatch request_id (entry+40, len entry+72) into g_rid so send helpers echo it
	addi t0, s4, 40
	lla  t1, g_rid_ptr
	sd   t0, 0(t1)
	ld   t0, 72(s4)
	lla  t1, g_rid_len
	sd   t0, 0(t1)
	# echo result entity (raw span) = response.result
	mv   a0, s1
	lla  a1, k_result
	li   a2, 6
	call map_find
	beqz a0, .Lhdr_ret
	mv   s2, a0                      # echo result entity ptr (was r13)
	call skip_value
	sub  s3, a0, s2                  # echo result len (was r14)
	# ---- inner {result:<echo result>, status:200} ----
	lla  s7, b_do_inner              # cursor tracker (was r15)
	mv   s6, s7
	li   a1, 2
	call w_map
	lla  a0, k_result
	call w_cstr
	mv   a1, s2                      # echo result ptr
	mv   a2, s3                      # echo result len
	call w_raw
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  t0, b_do_inner
	sub  s3, s6, t0                  # inner len (was r14)
	lla  a0, t_prim_any
	li   a1, 13
	lla  a2, b_do_inner
	mv   a3, s3
	lla  a4, do_inner_ch
	call ec_content_hash
	# ---- response data {result:<outer result entity>, status:200, request_id} ----
	lla  s7, b_do_data               # cursor tracker (was r15)
	mv   s6, s7
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	lla  a0, t_prim_any
	lla  a1, b_do_inner
	mv   a2, s3                      # inner len
	lla  a3, do_inner_ch
	call w_entity
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  t0, b_do_data
	sub  s3, s6, t0                  # response data len (was r14)
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_do_data
	mv   a3, s3
	lla  a4, do_data_ch
	call ec_content_hash
	# ---- envelope {root:<response entity>} ----
	lla  s7, b_do_env                # cursor tracker (was r15)
	mv   s6, s7
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_do_data
	mv   a2, s3                      # response data len
	lla  a3, do_data_ch
	call w_entity
	lla  t0, b_do_env
	sub  s3, s6, t0                  # envelope len (was r14)
	bswap32 t0, s3
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_do_env
	mv   a2, s3
	call write_all
.Lhdr_ret:
	ld   s6, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret
	.type store_delete, @function
store_delete:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   a3, a1                      # len -> a3 (canon_path: a1=ptr, a3=len)
	mv   a1, a0                      # ptr -> a1
	call canon_path                  # a0=canon, a2=len
	mv   s4, a0                      # canon (r13)
	mv   s5, a2                      # len (r14)
	lla  s1, store_idx               # rbx
	lla  t0, store_count
	ld   s3, 0(t0)                   # r12 = store_count
.Lsdl_scan:
	beqz s3, .Lsdl_ret
	ld   t0, 8(s1)                   # entry Klen
	bne  t0, s5, .Lsdl_next
	ld   a0, 0(s1)                   # entry key ptr
	mv   a1, s4
	mv   a2, s5
	call memeq
	bnez a0, .Lsdl_found
.Lsdl_next:
	addi s1, s1, 32
	addi s3, s3, -1
	j    .Lsdl_scan
.Lsdl_found:
	lla  t0, store_count
	ld   t1, 0(t0)
	addi t1, t1, -1
	slli t1, t1, 5
	lla  t2, store_idx
	add  t2, t2, t1                  # t2 = last entry
	ld   t0, 0(t2)
	sd   t0, 0(s1)
	ld   t0, 8(t2)
	sd   t0, 8(s1)
	ld   t0, 16(t2)
	sd   t0, 16(s1)
	ld   t0, 24(t2)
	sd   t0, 24(s1)
	lla  t0, store_count
	ld   t1, 0(t0)
	addi t1, t1, -1
	sd   t1, 0(t0)
.Lsdl_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# serve_tree_listing(a0 = raw prefix ptr, a1 = raw prefix len) — a trailing-slash tree get.
# Scans the per-fork store for canonical keys under /{localPeerID}/{prefix} (or under an
# absolute prefix verbatim), groups by immediate child segment, and emits a 200
# system/tree/listing {path, count, offset, entries:{seg→{hash, has_children}}}. Empty →
# falls back to the read-only typestore listing (system/type/) else a 200 empty listing.
	.type serve_tree_listing, @function
serve_tree_listing:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	lla  t0, g_lprefix_ptr
	sd   a0, 0(t0)
	lla  t0, g_lprefix_len
	sd   a1, 0(t0)
	mv   a3, a1                      # len -> a3 (canon_path wants rcx→a3)
	mv   a1, a0                      # ptr -> a1
	call canon_path                  # a0=cprefix ptr, a2=cprefix len
	lla  t0, g_cpref_ptr
	sd   a0, 0(t0)
	lla  t0, g_cpref_len
	sd   a2, 0(t0)
	lla  t0, listing_n
	sd   zero, 0(t0)
	lla  s1, store_idx               # rbx
	lla  t0, store_count
	ld   s2, 0(t0)                   # r12 = store_count
.Lstl_scan:
	beqz s2, .Lstl_emit
	ld   s3, 8(s1)                   # Klen (r13)
	lla  t0, g_cpref_len
	ld   t0, 0(t0)
	bltu s3, t0, .Lstl_next          # key shorter than prefix
	ld   a0, 0(s1)
	lla  t0, g_cpref_ptr
	ld   a1, 0(t0)
	lla  t0, g_cpref_len
	ld   a2, 0(t0)
	call memeq
	beqz a0, .Lstl_next
	ld   s4, 0(s1)                   # r14 = rest ptr base
	lla  t0, g_cpref_len
	ld   t0, 0(t0)
	add  s4, s4, t0                  # rest ptr
	mv   s5, s3                      # r15 = restlen
	sub  s5, s5, t0                  # restlen = Klen - cpref_len
	beqz s5, .Lstl_next              # exact prefix (the node itself)
	li   t0, 0                       # j = index of first '/'  (rcx)
.Lstl_slash:
	bgeu t0, s5, .Lstl_slashdone
	add  t1, s4, t0
	lbu  t1, 0(t1)
	li   t2, 0x2f
	beq  t1, t2, .Lstl_slashdone
	addi t0, t0, 1
	j    .Lstl_slash
.Lstl_slashdone:
	mv   a0, s4                      # seg ptr
	mv   a1, t0                      # seg len (= j)
	li   a4, 0                       # r8 = has_child
	bgeu a1, s5, .Lstl_add           # j < restlen → has deeper segment
	li   a4, 1
.Lstl_add:
	ld   a2, 16(s1)                  # blob ptr (leaf hash source)
	call add_listing_entry
.Lstl_next:
	addi s1, s1, 32
	addi s2, s2, -1
	j    .Lstl_scan
.Lstl_emit:
	lla  t0, listing_n
	ld   t0, 0(t0)
	bnez t0, .Lstl_build
	# no store children — fall back to the read-only typestore listing key, else 200 empty.
	lla  t0, g_lprefix_ptr
	ld   a1, 0(t0)
	lla  t0, g_lprefix_len
	ld   a2, 0(t0)
	call typestore_lookup
	beqz a0, .Lstl_build             # nothing → emit an empty listing
	mv   a1, a2                      # (send_get_ok: a0=ptr, a1=len)
	call send_get_ok
	j    .Lstl_done
.Lstl_build:
	call emit_listing
.Lstl_done:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# add_listing_entry(a0=seg ptr, a1=seg len, a2=blob ptr, a4=has_child) — insert-or-merge a
# child segment into listing_ents. A segment seen as both leaf and parent becomes has_children
# with a null hash (matching the reference: intermediate nodes carry hash:null).
	.type add_listing_entry, @function
add_listing_entry:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	mv   s0, sp
	mv   s4, a0                      # seg ptr (r13)
	mv   s5, a1                      # seg len (r14)
	mv   s3, a2                      # blob ptr (r15)
	mv   s2, a4                      # has_child (r12)
	# §6.3 — a leaf bound to a system/deletion-marker is omitted from listings.
	bnez s2, .Lale_notmarker
	mv   a0, s3
	lla  a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Lale_notmarker
	call get_text                    # a0=type ptr, a2=len
	li   t0, 22
	bne  a2, t0, .Lale_notmarker
	lla  a1, t_deletion_marker
	li   a2, 22                      # memeq: a0=type ptr, a1=needle, a2=len
	call memeq
	bnez a0, .Lale_ret               # deletion-marker leaf → skip
.Lale_notmarker:
	lla  s1, listing_ents            # rbx
	lla  t0, listing_n
	ld   s7, 0(t0)                   # r10 (counter — callee-saved across memeq)
.Lale_scan:
	beqz s7, .Lale_new
	ld   t0, 8(s1)
	bne  t0, s5, .Lale_scannext
	ld   a0, 0(s1)
	mv   a1, s4
	mv   a2, s5
	call memeq
	bnez a0, .Lale_found
.Lale_scannext:
	addi s1, s1, 32
	addi s7, s7, -1
	j    .Lale_scan
.Lale_found:
	beqz s2, .Lale_ret              # existing entry already covers this segment
	li   t0, 1
	sd   t0, 24(s1)                 # promote to parent
	sd   zero, 16(s1)              # parent hash is null
	j    .Lale_ret
.Lale_new:
	lla  t0, listing_n
	ld   a0, 0(t0)
	li   t0, 384
	bgeu a0, t0, .Lale_ret           # cap guard
	slli a0, a0, 5
	lla  s1, listing_ents
	add  s1, s1, a0
	sd   s4, 0(s1)
	sd   s5, 8(s1)
	bnez s2, .Lale_parent
	# leaf: hash = blob's content_hash field
	mv   a0, s3
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lale_hashnull
	call get_text                    # a0 = chash ptr
	sd   a0, 16(s1)
	j    .Lale_setchild
.Lale_hashnull:
	sd   zero, 16(s1)
	j    .Lale_setchild
.Lale_parent:
	sd   zero, 16(s1)
.Lale_setchild:
	sd   s2, 24(s1)
	lla  t0, listing_n
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
.Lale_ret:
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# sort_listing — bubble-sort listing_ents by (seg_len, then bytewise) for canonical map order.
	.type sort_listing, @function
sort_listing:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	lla  t0, listing_n
	ld   s3, 0(t0)                   # r12 = n
	li   t0, 2
	bltu s3, t0, .Lsl_ret
.Lsl_outer:
	li   s4, 0                       # i (r13)
	li   s5, 0                       # swapped flag (r14)
	lla  s1, listing_ents            # rbx
.Lsl_inner:
	addi t0, s3, -1                  # n-1
	bgeu s4, t0, .Lsl_outer_end
	# compare entry[i] (s1) vs entry[i+1] (s1+32)
	ld   a0, 8(s1)                   # a.len
	ld   a1, 40(s1)                  # b.len
	bgtu a0, a1, .Lsl_swap           # a longer → a after b
	bltu a0, a1, .Lsl_noswap
	# equal length → bytewise compare a vs b
	ld   a0, 0(s1)
	ld   a1, 32(s1)
	ld   a2, 8(s1)                   # len -> a2 (mcmp_lex: a0=a, a1=b, a2=len)
	call mcmp_lex                    # w0 = -1/0/1
	bgtz a0, .Lsl_swap
	j    .Lsl_noswap
.Lsl_swap:
	# swap the two 32-byte entries (4 quads)
	ld   t0, 0(s1)   ; ld t1, 32(s1) ; sd t1, 0(s1)   ; sd t0, 32(s1)
	ld   t0, 8(s1)   ; ld t1, 40(s1) ; sd t1, 8(s1)   ; sd t0, 40(s1)
	ld   t0, 16(s1)  ; ld t1, 48(s1) ; sd t1, 16(s1)  ; sd t0, 48(s1)
	ld   t0, 24(s1)  ; ld t1, 56(s1) ; sd t1, 24(s1)  ; sd t0, 56(s1)
	li   s5, 1
.Lsl_noswap:
	addi s1, s1, 32
	addi s4, s4, 1
	j    .Lsl_inner
.Lsl_outer_end:
	bnez s5, .Lsl_outer
.Lsl_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# mcmp_lex(a0=a, a1=b, a2=len) -> w0 = -1 if a<b, 0 if equal, 1 if a>b (bytewise). Leaf.
	.type mcmp_lex, @function
mcmp_lex:
.Lmcl:
	beqz a2, .Lmcl_eq
	lbu  t0, 0(a0)
	lbu  t1, 0(a1)
	bltu t0, t1, .Lmcl_lt
	bgtu t0, t1, .Lmcl_gt
	addi a0, a0, 1
	addi a1, a1, 1
	addi a2, a2, -1
	j    .Lmcl
.Lmcl_eq:
	li   a0, 0
	ret
.Lmcl_lt:
	li   a0, -1
	ret
.Lmcl_gt:
	li   a0, 1
	ret

# w_map_hdr(a1 = count) — emit a CBOR map header (major 5) for an arbitrary count via s6.
	.type w_map_hdr, @function
w_map_hdr:
	li   t0, 24
	bgeu a1, t0, .Lwmh_1
	li   t0, 0xa0
	or   t0, t0, a1
	sb   t0, 0(s6)
	addi s6, s6, 1
	ret
.Lwmh_1:
	li   t0, 256
	bgeu a1, t0, .Lwmh_2
	li   t0, 0xb8
	sb   t0, 0(s6)
	addi s6, s6, 1
	sb   a1, 0(s6)
	addi s6, s6, 1
	ret
.Lwmh_2:
	li   t0, 0xb9
	sb   t0, 0(s6)
	addi s6, s6, 1
	bswap16 t0, a1                   # 2-byte big-endian
	sh   t0, 0(s6)
	addi s6, s6, 2
	ret

# emit_listing — sort listing_ents, build the system/tree/listing entity, send it (200) by
# reusing send_get_ok (which wraps a verbatim entity blob as the response result).
	.type emit_listing, @function
emit_listing:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	call sort_listing
	# ---- listing data {path, count, offset, entries} ----
	lla  s6, b_list_data             # r15 = cursor
	li   a1, 4                       # w_map: a1 = n
	call w_map
	lla  a0, k_path
	call w_cstr
	lla  t0, g_lprefix_ptr
	ld   a1, 0(t0)
	lla  t0, g_lprefix_len
	ld   a2, 0(t0)
	call w_txt
	lla  a0, k_count
	call w_cstr
	lla  t0, listing_n
	ld   a1, 0(t0)                   # w_uint: a1 = val
	call w_uint
	lla  a0, k_offset
	call w_cstr
	li   a1, 0
	call w_uint
	lla  a0, k_entries
	call w_cstr
	lla  t0, listing_n
	ld   a1, 0(t0)                   # w_map_hdr: a1 = count
	call w_map_hdr
	li   s1, 0                       # i (r12)
.Lel_loop:
	lla  t0, listing_n
	ld   t0, 0(t0)
	bgeu s1, t0, .Lel_donemap
	mv   t0, s1
	slli t0, t0, 5
	lla  s2, listing_ents            # r13
	add  s2, s2, t0                  # entry
	ld   a1, 0(s2)                   # seg ptr
	ld   a2, 8(s2)                   # seg len
	call w_txt                       # key = segment
	li   a1, 2
	call w_map
	lla  a0, k_hash
	call w_cstr
	ld   t0, 16(s2)                  # hash ptr
	beqz t0, .Lel_null
	mv   a1, t0
	li   a2, 33
	call w_bstr
	j    .Lel_haschild
.Lel_null:
	li   t0, 0xf6                    # CBOR null
	sb   t0, 0(s6)
	addi s6, s6, 1
.Lel_haschild:
	lla  a0, k_has_children
	call w_cstr
	ld   t0, 24(s2)
	beqz t0, .Lel_false
	li   t0, 0xf5                    # true
	sb   t0, 0(s6)
	addi s6, s6, 1
	j    .Lel_next
.Lel_false:
	li   t0, 0xf4                    # false
	sb   t0, 0(s6)
	addi s6, s6, 1
.Lel_next:
	addi s1, s1, 1
	j    .Lel_loop
.Lel_donemap:
	lla  t0, b_list_data
	sub  s5, s6, t0                  # r14 = data len
	lla  a0, t_listing
	li   a1, 19
	lla  a2, b_list_data
	mv   a3, s5
	lla  a4, list_data_ch
	call ec_content_hash
	# ---- build the listing entity blob, hand to send_get_ok ----
	lla  s6, b_list_env              # r15 = cursor
	lla  a0, t_listing
	lla  a1, b_list_data
	mv   a2, s5
	lla  a3, list_data_ch
	call w_entity
	lla  t0, b_list_env
	sub  a1, s6, t0                  # entity len (send_get_ok: a1 = len)
	lla  a0, b_list_env              # ptr
	call send_get_ok
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# emit_sorted_included(a0 = count, a1 = table ptr) — emit an `included` CBOR map whose
# entries are sorted by their 33-byte key (ECF §4.2 canonical order). Each table entry is
# 40 bytes: [0]=key_ptr [8]=type_cstr [16]=data_ptr [24]=data_len [32]=chash_ptr.
# Emits via the global s6 cursor (w_map/w_bstr/w_entity), so s6 is left as the cursor.
	.type emit_sorted_included, @function
emit_sorted_included:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s2, a1                      # table ptr (r12)
	andi s3, a0, 0xff                # count (r13, zero-extended byte)
	# ---- bubble sort by 33-byte key ----
	mv   s4, s3                      # n (rcx) — sort bound
.Lesi_outer:
	li   t0, 1
	ble  s4, t0, .Lesi_sorted
	li   s1, 0                       # j = 0 (rbx)
.Lesi_inner:
	addi t0, s4, -1                  # n-1
	bgeu s1, t0, .Lesi_outer_dec
	mv   t0, s1
	li   t1, 40
	mul  t0, t0, t1
	add  s5, s2, t0                  # &entry[j] (r14)
	ld   a0, 0(s5)                   # key[j]
	ld   a1, 40(s5)                  # key[j+1]
	call mcmp33                      # w0 = signed byte diff
	blez a0, .Lesi_noswap
	# swap the two 40-byte entries (5 quads)
	ld   t0, 0(s5)   ; ld t1, 40(s5) ; sd t1, 0(s5)   ; sd t0, 40(s5)
	ld   t0, 8(s5)   ; ld t1, 48(s5) ; sd t1, 8(s5)   ; sd t0, 48(s5)
	ld   t0, 16(s5)  ; ld t1, 56(s5) ; sd t1, 16(s5)  ; sd t0, 56(s5)
	ld   t0, 24(s5)  ; ld t1, 64(s5) ; sd t1, 24(s5)  ; sd t0, 64(s5)
	ld   t0, 32(s5)  ; ld t1, 72(s5) ; sd t1, 32(s5)  ; sd t0, 72(s5)
.Lesi_noswap:
	addi s1, s1, 1
	j    .Lesi_inner
.Lesi_outer_dec:
	addi s4, s4, -1
	j    .Lesi_outer
.Lesi_sorted:
	# ---- emit map(count) then each entry ----
	mv   a1, s3                      # w_map: a1 = count
	call w_map
	li   s1, 0                       # i = 0 (rbx)
.Lesi_emit:
	bgeu s1, s3, .Lesi_done
	mv   t0, s1
	li   t1, 40
	mul  t0, t0, t1
	add  s5, s2, t0                  # &entry[i]
	ld   a1, 0(s5)                   # key ptr
	li   a2, 33
	call w_bstr
	ld   a0, 8(s5)                   # type cstr
	ld   a1, 16(s5)                  # data ptr
	ld   a2, 24(s5)                  # data len
	ld   a3, 32(s5)                  # chash ptr
	call w_entity
	addi s1, s1, 1
	j    .Lesi_emit
.Lesi_done:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# check_hello_negotiation(a0 = exec data map) -> a0 = 1 if the hello was rejected (a 400
# was sent), else 0. Rejects when params.data.hash_formats excludes "ecfv1-sha256" or
# params.data.key_types excludes "ed25519" (§4.5). Absent fields are not rejected (the
# happy path advertises our sets); this only fires on an explicit disjoint advertisement.
	.type check_hello_negotiation, @function
check_hello_negotiation:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a0                      # exec data map (r12)
	# params = map_find(exec, "params", 6)
	mv   a0, s1
	lla  a1, k_params
	li   a2, 6
	call map_find
	beqz a0, .Lhn_ok
	# pdata = map_find(params, "data", 4)
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lhn_ok
	mv   s2, a0                      # pdata (rbx)
	# hash_formats present? require "ecfv1-sha256"
	mv   a0, s2
	lla  a1, k_hfmts
	li   a2, 12
	call map_find
	beqz a0, .Lhn_kt                 # absent → skip (don't reject)
	lla  a1, v_ecfv1
	li   a2, 12                      # array_contains: a0=array, a1=needle, a2=len
	call array_contains
	bnez a0, .Lhn_kt
	li   a0, 400
	lla  a1, ec_incompat_hf
	call send_error
	li   a0, 1
	j    .Lhn_ret
.Lhn_kt:
	# key_types present? require "ed25519"
	mv   a0, s2
	lla  a1, k_ktypes
	li   a2, 9
	call map_find
	beqz a0, .Lhn_pid                # absent → still classify the peer_id's key-type
	lla  a1, v_ed25519
	li   a2, 7
	call array_contains
	bnez a0, .Lhn_pid
	li   a0, 400
	lla  a1, ec_unsup_kt
	call send_error
	li   a0, 1
	j    .Lhn_ret
.Lhn_pid:
	# §4.4/§7.1 agility: the hello's peer_id encodes its key-type as a multihash varint
	# prefix. Parse it; anything but ed25519 (key_type 1) — or an unparseable id — is an
	# unsupported algorithm → 400 unsupported_key_type (AGILITY-UNKNOWN-1, key_type 0xFD).
	mv   a0, s2                      # pdata
	lla  a1, k_peerid
	li   a2, 7
	call map_find
	beqz a0, .Lhn_ok                 # no peer_id → nothing to classify
	call get_text                    # a0 = ptr, a2 = len
	mv   a1, a2                      # len -> a1 (ec_peerid_parse: a0=ptr, a1=len, ...)
	lla  a2, g_pid_kt
	lla  a3, g_pid_ht
	lla  a4, b_pid_digest
	lla  a5, g_pid_dlen
	call ec_peerid_parse
	bnez a0, .Lhn_bad_kt             # parse failure → unsupported
	lla  t0, g_pid_kt
	ld   t0, 0(t0)
	li   t1, 1                       # 1 = ed25519 (the core floor)
	beq  t0, t1, .Lhn_proto
.Lhn_bad_kt:
	li   a0, 400
	lla  a1, ec_unsup_kt
	call send_error
	li   a0, 1
	j    .Lhn_ret
.Lhn_proto:
	# §4.5 `protocols` — the one negotiated field Required with NO default, so unlike the
	# two sets above ABSENT is not lenient here, and the field carries TWO §4.7 rows:
	#   absent or EMPTY    -> 400 invalid_request      (a peer that names no version has made
	#                                                   no incompatible-VERSION claim; the
	#                                                   request is malformed, not incompatible)
	#   non-empty disjoint -> 400 incompatible_protocol (row 1)
	#
	# ORDERED AFTER THE key_type GATE ABOVE, AND THAT ORDER IS THE POINT (F56):
	# AGILITY-UNKNOWN-1 sends key_type 0xFD **and** protocols ["entity-core/v7"] in ONE
	# hello, so both gates match and whichever runs first names the failure. §4.5 fixes no
	# precedence between them, so the choice is stated here rather than left to the order
	# these blocks happen to sit in.
	mv   a0, s2                      # pdata
	lla  a1, k_protos
	li   a2, 9
	call map_find
	beqz a0, .Lhn_bad_proto          # ABSENT -> 400 invalid_request (no default)
	mv   s3, a0                      # the protocols array node
	call read_head                   # a0 = after-head, a1 = major(4), a2 = element count
	li   t0, 4
	bne  a1, t0, .Lhn_bad_proto      # not an array -> malformed
	beqz a2, .Lhn_bad_proto          # EMPTY -> 400 invalid_request, same row as absent
	mv   a0, s3
	lla  a1, v_ecore
	li   a2, 15                      # "entity-core/1.0"
	call array_contains
	bnez a0, .Lhn_ok
	li   a0, 400
	lla  a1, ec_incompat_proto
	call send_error
	li   a0, 1
	j    .Lhn_ret
.Lhn_bad_proto:
	li   a0, 400
	lla  a1, ec_invalid_request
	call send_error
	li   a0, 1
	j    .Lhn_ret
.Lhn_ok:
	li   a0, 0
.Lhn_ret:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# uri_is_connect(a0 = exec data map) -> a0 = 1 if data.uri addresses the connect handler.
# A PREDICATE: it decides nothing, and §4.7's row 10 verdict stays at the call site.
#
# It accepts all three §1.4 spellings — bare peer-relative "system/protocol/connect",
# "/{peer}/system/protocol/connect" and "entity://{peer}/system/protocol/connect" —
# because the address gate has already established the peer segment is ours and the only
# question left is which handler is named. derive_handler is NOT reusable here: it strips
# the scheme form only and defaults everything else to system/tree, which is right for the
# scope check it feeds and wrong for this. validate's own connectURI is the BARE form.
	.type uri_is_connect, @function
uri_is_connect:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	li   s3, 0                       # result
	lla  a1, k_uri
	li   a2, 3
	call map_find                    # a0 = exec
	beqz a0, .Luic_ret
	call get_text                    # a0 = ptr, a2 = len
	mv   s1, a0                      # cursor
	mv   s2, a2                      # remaining
	li   t0, 9
	blt  s2, t0, .Luic_slash
	mv   a0, s1
	lla  a1, s_entity_scheme
	li   a2, 9
	call memeq
	beqz a0, .Luic_slash
	addi s1, s1, 9                   # past "entity://" -> "{peer}/rest"
	addi s2, s2, -9
	j    .Luic_scan
.Luic_slash:
	beqz s2, .Luic_ret
	lbu  t0, 0(s1)
	li   t1, 0x2f
	bne  t0, t1, .Luic_cmp           # no leading slash and no scheme -> already relative
	addi s1, s1, 1                   # "/{peer}/rest"
	addi s2, s2, -1
.Luic_scan:
	beqz s2, .Luic_ret               # one segment, no slash -> not a handler path
	lbu  t0, 0(s1)
	li   t1, 0x2f
	beq  t0, t1, .Luic_skip
	addi s1, s1, 1
	addi s2, s2, -1
	j    .Luic_scan
.Luic_skip:
	addi s1, s1, 1                   # past the slash that ends the peer segment
	addi s2, s2, -1
.Luic_cmp:
	li   t0, 23                      # "system/protocol/connect"
	bne  s2, t0, .Luic_ret
	mv   a0, s1
	lla  a1, va_sysconnect
	li   a2, 23
	call memeq
	mv   s3, a0
.Luic_ret:
	mv   a0, s3
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# record_hello_peer(a0 = exec data map) — latch the accepted-hello state for §4.7 rows 8/9.
# Called ONLY past every refusal, from the one site that is about to build a 200: a rejected
# hello must leave the connection fresh so the caller may retry with a conformant one, and a
# latch set at parse time would forbid that retry.
# Records params.data.peer_id (row 8's second input) when the hello names one; absent leaves
# g_hello_peer_len at 0, which the authenticate-side comparison reads as "nothing to compare".
	.type record_hello_peer, @function
record_hello_peer:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	lla  t0, g_hello_peer_len
	sd   zero, 0(t0)
	lla  a1, k_params
	li   a2, 6
	call map_find                    # a0 = exec
	beqz a0, .Lrhp_done
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lrhp_done
	lla  a1, k_peerid
	li   a2, 7
	call map_find
	beqz a0, .Lrhp_done
	call get_text                    # a0 = ptr, a2 = len
	li   t0, 128                     # b_hello_peer is 128 bytes — a longer id is not one
	bgtu a2, t0, .Lrhp_done
	mv   s1, a2                      # len
	mv   a1, a0                      # src
	lla  a0, b_hello_peer            # dst
	mv   a2, s1
	call mcpy
	lla  t0, g_hello_peer_len
	sd   s1, 0(t0)
.Lrhp_done:
	li   t0, 1
	lla  t1, g_hello_done
	sd   t0, 0(t1)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# array_contains(a0 = array value ptr, a1 = needle ptr, a2 = needle len) -> a0 = 1|0.
# Iterates a CBOR text array; matches by exact bytes. (Elements assumed text — true for
# hash_formats / key_types; a non-text element just won't match.)
	.type array_contains, @function
array_contains:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s3, a1                      # needle ptr (r13)
	mv   s4, a2                      # needle len (r14)
	call read_head                   # a0=after-head, a1=major(4), a2=count
	mv   s1, a0                      # cursor (r12)
	mv   s2, a2                      # remaining count (rbx)
.Lac_l:
	beqz s2, .Lac_no
	mv   a0, s1
	call read_head                   # a0=text start, a2=len (major 3)
	mv   t0, a0                      # element start (survives memeq)  (r8)
	add  s1, a0, a2                  # advance cursor past element text
	bne  a2, s4, .Lac_next
	mv   a1, t0                      # element start
	mv   a0, s3                      # needle ptr ; a2 already = len
	call memeq
	bnez a0, .Lac_yes
.Lac_next:
	addi s2, s2, -1
	j    .Lac_l
.Lac_yes:
	li   a0, 1
	j    .Lac_ret
.Lac_no:
	li   a0, 0
.Lac_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret
# =====================================================================
# verify_get_auth(a0 = exec data map) -> a0 = 0 authorized, 1 rejected (401 sent).
# §5.2 auth-class (401) stage: the request must carry an `author`, that author's system/peer
# entity must be in `included` (→ its public_key), and `included` must hold a system/signature
# with signer=author and target=root.content_hash that Ed25519-verifies over that 33-byte
# hash. A missing author / unresolvable pubkey / absent-or-bad signature → 401
# authentication_failed. (Capability-class 403 checks are a separate, later stage.)
	.type verify_get_auth, @function
verify_get_auth:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)                 # s1=author ptr(rbx), s2=included(r12)
	sd   s2, 24(sp)
	sd   s3, 32(sp)                 # s3=root_ch(r13), s4=pubkey(r14)
	sd   s4, 40(sp)
	sd   s6, 48(sp)                # s6=exec data map (r15) — preserve global cursor slot
	mv   s0, sp
	mv   s6, a0                    # exec data map
	# A. author present?
	mv   a0, s6
	lla  a1, k_author
	li   a2, 6
	call map_find
	beqz a0, .Lvga_401
	call get_text                   # a0=author ptr, a2=33
	mv   s1, a0                    # author ptr
	# B. included present?
	lla  a0, b_req
	lla  a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lvga_401
	mv   s2, a0                    # included map
	# C. author's peer entity in included → public_key
	mv   a0, s2
	mv   a1, s1
	call included_find_by_key
	beqz a0, .Lvga_401
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvga_401
	lla  a1, ka_pubkey
	li   a2, 10
	call map_find
	beqz a0, .Lvga_401
	call get_text                   # a0=pubkey ptr, a2=32
	mv   s4, a0                    # pubkey ptr
	# D. root.content_hash
	lla  a0, b_req
	lla  a1, k_root
	li   a2, 4
	call map_find
	beqz a0, .Lvga_401
	lla  a1, k_chash
	li   a2, 12
	call map_find
	beqz a0, .Lvga_401
	call get_text                   # a0=root_ch ptr, a2=33
	mv   s3, a0                    # root_ch ptr
	# E. request signature: signer==author, target==root_ch
	mv   a0, s2                    # included
	mv   a1, s1                    # author
	mv   a2, s3                    # root_ch
	call find_req_sig               # a0 = 64-byte signature ptr | 0
	beqz a0, .Lvga_401
	# F. Ed25519 verify over root_ch
	mv   a3, a0                     # signature
	mv   a0, s4                    # pubkey
	mv   a1, s3                    # message = root_ch
	li   a2, 33
	call ec_ed25519_verify
	bnez a0, .Lvga_401
	li   a0, 0                     # authorized
	j    .Lvga_ret
.Lvga_401:
	li   a0, 401
	lla  a1, ec_auth_failed
	call send_error
	li   a0, 1
.Lvga_ret:
	ld   s6, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret
verify_multisig_granter:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)                  # s1=i/loop(rbx), s2=included(r12)
	sd   s2, 24(sp)
	sd   s3, 32(sp)                  # s3=cap_hash(r13), s4=signer cursor(r14)
	sd   s4, 40(sp)
	sd   s6, 48(sp)                  # s6=N(r15) — preserve global cursor slot
	mv   s0, sp
	mv   s3, a1                      # cap_hash
	mv   s2, a2                      # included
	mv   s1, a0                      # granter map (temporarily in rbx→s1)
	# threshold
	mv   a0, s1
	adr_l a1, ka_threshold
	li   a2, 9
	call map_find
	beqz a0, .Lvms_reject
	call read_head                  # a2 = threshold
	adr_l t0, g_ms_thresh
	sd   a2, 0(t0)
	li   t0, 2
	bltu a2, t0, .Lvms_reject       # threshold < 2
	# (M3's root-only rule is enforced by the caller, against the TOKEN's `parent` field —
	# testing the GRANTER map for a `parent` key is vacuous, since {signers, threshold}
	# never carries one.)
	# signers array
	mv   a0, s1
	adr_l a1, ka_signers
	li   a2, 7
	call map_find
	beqz a0, .Lvms_reject
	call read_head                  # a0=first elem, a1=major, a2=count
	li   t0, 4
	bne  a1, t0, .Lvms_reject
	mv   s6, a2                      # N
	mv   s4, a0                      # signer cursor
	li   t0, 2
	bltu s6, t0, .Lvms_reject       # N < 2
	li   t0, 32
	bgtu s6, t0, .Lvms_reject       # bound the scratch array
	adr_l t0, g_ms_thresh
	ld   t0, 0(t0)
	bgtu t0, s6, .Lvms_reject       # threshold > N
	# collect signer-hash pointers into g_ms_sigs[0..N)
	li   s1, 0                      # i
.Lvms_collect:
	bgeu s1, s6, .Lvms_collected
	mv   a0, s4
	call get_text                   # a0 = signer ptr (33)
	adr_l t0, g_ms_sigs
	slli t1, s1, 3
	add  t0, t0, t1
	sd   a0, 0(t0)
	mv   a0, s4
	call skip_value
	mv   s4, a0
	addi s1, s1, 1
	j    .Lvms_collect
.Lvms_collected:
	# distinctness — reject if any two signers are equal
	li   s1, 0                      # i
.Lvms_di:
	bgeu s1, s6, .Lvms_distinct_ok
	addi s4, s1, 1                  # j = i+1
.Lvms_dj:
	bgeu s4, s6, .Lvms_di_next
	adr_l t0, g_ms_sigs
	slli t1, s1, 3
	add  t1, t0, t1
	ld   a0, 0(t1)
	slli t2, s4, 3
	add  t2, t0, t2
	ld   a1, 0(t2)
	li   a2, 33
	call memeq
	bnez a0, .Lvms_reject           # duplicate signer
	addi s4, s4, 1
	j    .Lvms_dj
.Lvms_di_next:
	addi s1, s1, 1
	j    .Lvms_di
.Lvms_distinct_ok:
	adr_l t0, g_ms_valid
	sd   zero, 0(t0)
	adr_l t0, g_ms_local
	sd   zero, 0(t0)
	li   s1, 0                      # i
.Lvms_vloop:
	bgeu s1, s6, .Lvms_counted
	adr_l t0, g_ms_sigs
	slli t1, s1, 3
	add  t0, t0, t1
	ld   s4, 0(t0)                  # signer i ptr
	# local ∈ signers?
	mv   a0, s4
	adr_l a1, g_identity_hash
	li   a2, 33
	call memeq
	beqz a0, .Lvms_notlocal
	li   t0, 1
	adr_l t1, g_ms_local
	sd   t0, 0(t1)
.Lvms_notlocal:
	# a valid signature by signer i over cap_hash?
	mv   a0, s2
	mv   a1, s4
	mv   a2, s3
	call find_req_sig               # a0 = 64-byte sig ptr | 0
	beqz a0, .Lvms_vnext
	adr_l t0, g_ms_sigptr
	sd   a0, 0(t0)
	# signer i public_key from its system/peer in included
	mv   a0, s2
	mv   a1, s4
	call included_find_by_key
	beqz a0, .Lvms_vnext
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvms_vnext
	adr_l a1, ka_pubkey
	li   a2, 10
	call map_find
	beqz a0, .Lvms_vnext
	call get_text                   # a0 = pubkey ptr
	mv   a1, s3                     # message = cap_hash
	li   a2, 33
	adr_l t0, g_ms_sigptr
	ld   a3, 0(t0)                  # signature
	call ec_ed25519_verify
	bnez a0, .Lvms_vnext            # invalid signature
	adr_l t0, g_ms_valid
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
.Lvms_vnext:
	addi s1, s1, 1
	j    .Lvms_vloop
.Lvms_counted:
	adr_l t0, g_ms_local
	ld   t0, 0(t0)
	beqz t0, .Lvms_reject           # THIS peer must be a co-signer
	adr_l t0, g_ms_valid
	ld   t0, 0(t0)
	adr_l t1, g_ms_thresh
	ld   t1, 0(t1)
	bltu t0, t1, .Lvms_reject       # fewer than threshold valid signatures
	li   a0, 0                      # accept
	j    .Lvms_ret
.Lvms_reject:
	li   a0, 1
.Lvms_ret:
	ld   s6, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# §5.5a canonicalization + §5.6 attenuation — the delegation-chain interior.
# (Port of asm-arm64/src/dispatch.s; same protocol logic, RV64 LP64D registers.)
# =====================================================================
#
# peerid_of(a0 = included, a1 = hash33, a2 = out ptr, a3 = out_len ptr) -> a0 = 1|0.
# The §5.5a canonicalization FRAME for a link is its granter's peer_id, which is NOT on
# the wire: it is derived from the granter's system/peer entity in `included` — the same
# entity the link's signature is verified against — by re-running the base58 peer-id
# format over its public_key.
	.type peerid_of, @function
peerid_of:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a2                      # out
	mv   s2, a3                      # out_len ptr
	call included_find_by_key
	beqz a0, .Lpio_no
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lpio_no
	adr_l a1, ka_pubkey
	li   a2, 10
	call map_find
	beqz a0, .Lpio_no
	call get_text                    # a0 = pubkey ptr, a2 = len
	li   t0, 32
	bne  a2, t0, .Lpio_no
	mv   s3, a0
	li   a0, 1                       # key_type = ed25519
	li   a1, 0                       # hash_type = 0 (identity)
	mv   a2, s3
	li   a3, 32
	mv   a4, s1
	li   a5, 128
	mv   a6, s2
	call ec_peerid_format
	bnez a0, .Lpio_no
	li   a0, 1
	j    .Lpio_ret
.Lpio_no:
	li   a0, 0
.Lpio_ret:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# canon(a0 = pattern, a1 = len, a2 = frame, a3 = frame len, a4 = out) -> a0 = out len.
# §5.5a: a leading "/" means the pattern already names a peer position — copy verbatim;
# anything else is peer-RELATIVE and becomes "/" + frame + "/" + pattern.
# Bare "*" gets NO special case and deliberately must not: it falls out of the general rule
# as "/{frame}/*", which is exactly what §5.5a says it means — the granter's own namespace,
# never a universal cross-peer wildcard. Special-casing it is how the bare-star-is-universal
# defect (A-PD-017, and swift/sql's frame over-scoping) gets built.
	.type canon, @function
canon:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s1, a0                      # pattern
	mv   s2, a1                      # pattern len
	mv   s3, a2                      # frame
	mv   s4, a3                      # frame len
	mv   s5, a4                      # out
	beqz s2, .Lcn_rel
	lbu  t0, 0(s1)
	li   t1, 0x2f
	bne  t0, t1, .Lcn_rel
	mv   a0, s5
	mv   a1, s1
	mv   a2, s2
	call mcpy
	mv   a0, s2
	j    .Lcn_ret
.Lcn_rel:
	li   t0, 0x2f
	sb   t0, 0(s5)
	addi a0, s5, 1
	mv   a1, s3
	mv   a2, s4
	call mcpy                        # a0 = dst + frame len
	li   t0, 0x2f
	sb   t0, 0(a0)
	addi a0, a0, 1
	mv   a1, s1
	mv   a2, s2
	call mcpy
	sub  a0, a0, s5                  # total canonical length
.Lcn_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# pat_covers(a0 = child pat, a1 = child len, a2 = parent pat, a3 = parent len) -> a0 = 1|0.
# Both canonical, both absolute. Segment-wise:
#   parent "*" as the LAST segment → covers everything remaining
#   parent "*" mid-pattern         → covers exactly one child segment, whatever it is
#   parent literal                 → the child segment must be that literal; a child "*"
#                                    here is BROADER than the parent and is refused
# Both exhausted together → covered; either alone → not covered.
	.type pat_covers, @function
# s1=child ptr s2=child len s3=parent ptr s4=parent len s5=ci s7=pi s8=ps s9=pl s10=cs s11=cl
pat_covers:
	addi sp, sp, -96
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	sd   s9, 72(sp)
	sd   s10, 80(sp)
	sd   s11, 88(sp)
	mv   s0, sp
	mv   s1, a0                      # child ptr
	mv   s2, a1                      # child len
	mv   s3, a2                      # parent ptr
	mv   s4, a3                      # parent len
	beqz s2, .Lpc_no
	beqz s4, .Lpc_no
	li   t1, 0x2f
	lbu  t0, 0(s1)
	bne  t0, t1, .Lpc_no
	lbu  t0, 0(s3)
	bne  t0, t1, .Lpc_no
	li   s5, 1                       # ci
	li   s7, 1                       # pi
.Lpc_loop:
	bltu s7, s4, .Lpc_pseg
	bgeu s5, s2, .Lpc_yes            # parent exhausted → covered iff child is too
	j    .Lpc_no
.Lpc_pseg:
	# Read the PARENT segment BEFORE testing whether the child is exhausted: a trailing "*"
	# covers the remainder INCLUDING the empty one. "/{peer}/*" authorizes that peer's
	# namespace, and listing the namespace's own root ("/{peer}/") is inside it, not above
	# it. Testing child-exhaustion first refuses every root listing while every deeper path
	# still works, which reads as a permissions bug rather than a matcher bug.
	add  s8, s3, s7                  # ps
	li   s9, 0                       # pl
.Lpc_pscan:
	add  t0, s7, s9
	bgeu t0, s4, .Lpc_pdone
	add  t1, s8, s9
	lbu  t2, 0(t1)
	li   t3, 0x2f
	beq  t2, t3, .Lpc_pdone
	addi s9, s9, 1
	j    .Lpc_pscan
.Lpc_pdone:
	li   t0, 1
	bne  s9, t0, .Lpc_child
	lbu  t1, 0(s8)
	li   t2, 0x2a
	bne  t1, t2, .Lpc_child
	add  t0, s7, s9
	bgeu t0, s4, .Lpc_yes            # trailing "*" — covers the rest, empty included
.Lpc_child:
	bgeu s5, s2, .Lpc_no             # child exhausted under a non-trailing-star parent
	add  s10, s1, s5                 # cs
	li   s11, 0                      # cl
.Lpc_cscan:
	add  t0, s5, s11
	bgeu t0, s2, .Lpc_cdone
	add  t1, s10, s11
	lbu  t2, 0(t1)
	li   t3, 0x2f
	beq  t2, t3, .Lpc_cdone
	addi s11, s11, 1
	j    .Lpc_cscan
.Lpc_cdone:
	li   t0, 1
	bne  s9, t0, .Lpc_literal
	lbu  t1, 0(s8)
	li   t2, 0x2a
	beq  t1, t2, .Lpc_advance        # mid-pattern "*" — matches this one child segment
.Lpc_literal:
	li   t0, 1
	bne  s11, t0, .Lpc_cmp
	lbu  t1, 0(s10)
	li   t2, 0x2a
	beq  t1, t2, .Lpc_no             # a "*" child under a literal parent is BROADER
.Lpc_cmp:
	bne  s11, s9, .Lpc_no
	mv   a0, s10
	mv   a1, s8
	mv   a2, s11
	call memeq
	beqz a0, .Lpc_no
.Lpc_advance:
	add  s5, s5, s11
	addi s5, s5, 1
	add  s7, s7, s9
	addi s7, s7, 1
	j    .Lpc_loop
.Lpc_yes:
	li   a0, 1
	j    .Lpc_ret
.Lpc_no:
	li   a0, 0
.Lpc_ret:
	ld   s11, 88(sp)
	ld   s10, 80(sp)
	ld   s9, 72(sp)
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 96
	ret

# arr_subset_framed(a0 = sub array, a1 = super array) -> a0 = 1 if every element of `sub`
# is covered by some element of `super` under §5.5a framing. The two sides canonicalize
# against DIFFERENT frames — g_sfr_ptr/len for `sub`, g_qfr_ptr/len for `super` — which the
# caller sets, so the exclude direction reverses them without copying a frame.
	.type arr_subset_framed, @function
arr_subset_framed:
	addi sp, sp, -96
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	sd   s9, 72(sp)
	sd   s10, 80(sp)
	mv   s0, sp
	mv   s7, a1                      # super array
	call read_head                   # a0 = sub array
	li   t0, 4
	bne  a1, t0, .Lasf_no
	mv   s1, a0                      # sub cursor
	mv   s2, a2                      # sub remaining
.Lasf_outer:
	beqz s2, .Lasf_yes
	mv   a0, s1
	call read_head                   # a0 = elem bytes, a2 = elem len
	mv   s3, a0
	mv   s4, a2
	add  s1, a0, a2
	addi s2, s2, -1
	mv   a0, s3
	mv   a1, s4
	adr_l t0, g_sfr_ptr
	ld   a2, 0(t0)
	adr_l t0, g_sfr_len
	ld   a3, 0(t0)
	adr_l a4, b_canon_a
	call canon
	mv   s5, a0                      # canonical child length
	mv   a0, s7
	call read_head
	li   t0, 4
	bne  a1, t0, .Lasf_no
	mv   s8, a0                      # super cursor
	mv   s9, a2                      # super remaining
.Lasf_inner:
	beqz s9, .Lasf_no                # no super element covers this sub element
	mv   a0, s8
	call read_head
	mv   s10, a0
	mv   t1, a2
	add  s8, a0, a2
	addi s9, s9, -1
	mv   a0, s10
	mv   a1, t1
	adr_l t0, g_qfr_ptr
	ld   a2, 0(t0)
	adr_l t0, g_qfr_len
	ld   a3, 0(t0)
	adr_l a4, b_canon_b
	call canon
	mv   a3, a0
	adr_l a0, b_canon_a
	mv   a1, s5
	adr_l a2, b_canon_b
	call pat_covers
	bnez a0, .Lasf_outer
	j    .Lasf_inner
.Lasf_yes:
	li   a0, 1
	j    .Lasf_ret
.Lasf_no:
	li   a0, 0
.Lasf_ret:
	ld   s10, 80(sp)
	ld   s9, 72(sp)
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 96
	ret

# set_frames_cp / set_frames_pc — point the sub/super frame pair at the child/parent frames
# in the given order. Clobbers t0/t1 only.
	.type set_frames_cp, @function
set_frames_cp:
	adr_l t0, g_cfr
	adr_l t1, g_sfr_ptr
	sd   t0, 0(t1)
	adr_l t0, g_cfrlen
	ld   t0, 0(t0)
	adr_l t1, g_sfr_len
	sd   t0, 0(t1)
	adr_l t0, g_pfr
	adr_l t1, g_qfr_ptr
	sd   t0, 0(t1)
	adr_l t0, g_pfrlen
	ld   t0, 0(t0)
	adr_l t1, g_qfr_len
	sd   t0, 0(t1)
	ret
	.type set_frames_pc, @function
set_frames_pc:
	adr_l t0, g_pfr
	adr_l t1, g_sfr_ptr
	sd   t0, 0(t1)
	adr_l t0, g_pfrlen
	ld   t0, 0(t0)
	adr_l t1, g_sfr_len
	sd   t0, 0(t1)
	adr_l t0, g_cfr
	adr_l t1, g_qfr_ptr
	sd   t0, 0(t1)
	adr_l t0, g_cfrlen
	ld   t0, 0(t0)
	adr_l t1, g_qfr_len
	sd   t0, 0(t1)
	ret

# dim_subset(a0 = child scope map, a1 = parent scope map, a2 = framed) -> a0 = 1|0.
# One scope dimension, child ⊆ parent. `framed` selects §5.5a canonicalization, which scopes
# the RESOURCE dimension ONLY — handlers/operations/peers are id-scope and take no frame.
# Over-applying the frame is the swift/sql defect: a universal parent grant stops covering
# any child grant the moment the two have different granters, and every delegated cap 403s.
# Both halves of the spec's scope_subset are here: child includes covered by parent includes,
# AND every parent exclude inherited by some child exclude.
	.type dim_subset, @function
dim_subset:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s1, a0                      # child scope
	mv   s2, a1                      # parent scope
	mv   s3, a2                      # framed
	mv   a0, s1
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lds_no
	mv   s4, a0                      # child include
	mv   a0, s2
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lds_no
	mv   s5, a0                      # parent include
	beqz s3, .Lds_inc_plain
	call set_frames_cp               # sub ← child frame, super ← parent frame
	mv   a0, s4
	mv   a1, s5
	call arr_subset_framed
	j    .Lds_inc_done
.Lds_inc_plain:
	mv   a0, s4
	mv   a1, s5
	call array_subset_star
.Lds_inc_done:
	beqz a0, .Lds_no
	# Exclude inheritance runs in the REVERSE direction from includes: each PARENT exclude
	# must be covered by some CHILD exclude, because the child must exclude at least as much
	# as its parent did. A child that simply drops the parent's exclude widens itself.
	mv   a0, s2
	adr_l a1, ka_exclude
	li   a2, 7
	call map_find
	beqz a0, .Lds_yes                # parent excludes nothing → nothing to inherit
	mv   s5, a0                      # parent exclude
	mv   a0, s1
	adr_l a1, ka_exclude
	li   a2, 7
	call map_find
	beqz a0, .Lds_no                 # parent excluded, child does not → widened
	mv   s4, a0                      # child exclude
	beqz s3, .Lds_exc_plain
	call set_frames_pc               # sub ← parent frame, super ← child frame
	mv   a0, s5
	mv   a1, s4
	call arr_subset_framed
	j    .Lds_ret
.Lds_exc_plain:
	mv   a0, s5
	mv   a1, s4
	call array_subset_star
	j    .Lds_ret
.Lds_yes:
	li   a0, 1
	j    .Lds_ret
.Lds_no:
	li   a0, 0
.Lds_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# map_attenuated(a0 = from map | 0, a1 = to map | 0) -> a0 = 1|0.
# Every key of `from` must appear in `to` with a byte-identical value. Used twice, in
# opposite directions: CONSTRAINTS (every parent key must survive on the child — a dropped
# key widens it) and ALLOWANCES (every child key must already exist on the parent — an added
# key widens it). Absent `from` → vacuously attenuated.
	.type map_attenuated, @function
map_attenuated:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	mv   s0, sp
	beqz a0, .Lma_yes
	mv   s7, a1                      # to
	call read_head                   # a0 = from
	li   t0, 5
	bne  a1, t0, .Lma_no
	mv   s1, a0                      # cursor
	mv   s2, a2                      # pair count
	beqz s2, .Lma_yes
	beqz s7, .Lma_no
.Lma_loop:
	beqz s2, .Lma_yes
	mv   a0, s1
	call read_head                   # a0 = key bytes, a2 = key len
	mv   s3, a0
	mv   s4, a2
	add  s1, a0, a2                  # value ptr
	mv   a0, s7
	mv   a1, s3
	mv   a2, s4
	call map_find
	beqz a0, .Lma_no
	mv   s3, a0                      # the counterpart value
	mv   a0, s1
	call skip_value
	mv   s4, a0                      # next pair
	sub  s5, a0, s1                  # this value's byte length
	mv   a0, s3
	call skip_value
	sub  a0, a0, s3                  # counterpart length
	bne  a0, s5, .Lma_no
	mv   a2, s5
	mv   a0, s1
	mv   a1, s3
	call memeq
	beqz a0, .Lma_no
	mv   s1, s4
	addi s2, s2, -1
	j    .Lma_loop
.Lma_yes:
	li   a0, 1
	j    .Lma_ret
.Lma_no:
	li   a0, 0
.Lma_ret:
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# grant_subset_framed(a0 = child grant, a1 = parent grant) -> a0 = 1|0.
# All four §5.6 scope dimensions plus constraints and allowances. Only RESOURCES is framed.
	.type grant_subset_framed, @function
grant_subset_framed:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a0                      # child grant
	mv   s2, a1                      # parent grant
	# handlers — id-scope, no frame
	mv   a0, s1
	adr_l a1, ka_handlers
	li   a2, 8
	call map_find
	beqz a0, .Lgsf_no
	mv   s3, a0
	mv   a0, s2
	adr_l a1, ka_handlers
	li   a2, 8
	call map_find
	beqz a0, .Lgsf_no
	mv   a1, a0
	mv   a0, s3
	li   a2, 0
	call dim_subset
	beqz a0, .Lgsf_no
	# operations — id-scope, no frame
	mv   a0, s1
	adr_l a1, ka_operations
	li   a2, 10
	call map_find
	beqz a0, .Lgsf_no
	mv   s3, a0
	mv   a0, s2
	adr_l a1, ka_operations
	li   a2, 10
	call map_find
	beqz a0, .Lgsf_no
	mv   a1, a0
	mv   a0, s3
	li   a2, 0
	call dim_subset
	beqz a0, .Lgsf_no
	# resources — THE framed dimension, and the only one
	mv   a0, s1
	adr_l a1, ka_resources
	li   a2, 9
	call map_find
	beqz a0, .Lgsf_peers             # child names no resources → nothing to bound
	mv   s3, a0
	mv   a0, s2
	adr_l a1, ka_resources
	li   a2, 9
	call map_find
	beqz a0, .Lgsf_no
	mv   a1, a0
	mv   a0, s3
	li   a2, 1
	call dim_subset
	beqz a0, .Lgsf_no
.Lgsf_peers:
	# peers — id-scope; absent defaults to {include:[local_peer_id]} on BOTH sides, so an
	# absent-vs-absent pair is trivially a subset and needs no synthesised map.
	mv   a0, s1
	adr_l a1, ka_peers
	li   a2, 5
	call map_find
	beqz a0, .Lgsf_maps
	mv   s3, a0
	mv   a0, s2
	adr_l a1, ka_peers
	li   a2, 5
	call map_find
	beqz a0, .Lgsf_no
	mv   a1, a0
	mv   a0, s3
	li   a2, 0
	call dim_subset
	beqz a0, .Lgsf_no
.Lgsf_maps:
	# constraints: every parent key retained on the child, byte-equal
	mv   a0, s2
	adr_l a1, ka_constraints
	li   a2, 11
	call map_find
	mv   s3, a0
	mv   a0, s1
	adr_l a1, ka_constraints
	li   a2, 11
	call map_find
	mv   a1, a0
	mv   a0, s3
	call map_attenuated
	beqz a0, .Lgsf_no
	# allowances: every child key pre-existing on the parent, byte-equal
	mv   a0, s1
	adr_l a1, ka_allowances
	li   a2, 10
	call map_find
	mv   s3, a0
	mv   a0, s2
	adr_l a1, ka_allowances
	li   a2, 10
	call map_find
	mv   a1, a0
	mv   a0, s3
	call map_attenuated
	j    .Lgsf_ret
.Lgsf_no:
	li   a0, 0
.Lgsf_ret:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# is_attenuated(a0 = child token data, a1 = parent token data) -> a0 = 1|0.
# §5.6 with the per-link §5.5a frames already in g_cfr / g_pfr: every child grant covered by
# some parent grant, then the expiration rule.
	.type is_attenuated, @function
is_attenuated:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	mv   s0, sp
	mv   s1, a0                      # child token data
	mv   s2, a1                      # parent token data
	adr_l a1, ka_grants
	li   a2, 6
	call map_find
	beqz a0, .Lia_no
	mv   s3, a0                      # child grants array
	mv   a0, s2
	adr_l a1, ka_grants
	li   a2, 6
	call map_find
	beqz a0, .Lia_no
	mv   s4, a0                      # parent grants array
	mv   a0, s3
	call read_head
	li   t0, 4
	bne  a1, t0, .Lia_no
	mv   s3, a0                      # child grant cursor
	mv   s5, a2                      # child grants remaining
.Lia_child:
	beqz s5, .Lia_expiry
	mv   a0, s4
	call read_head
	li   t0, 4
	bne  a1, t0, .Lia_no
	mv   s7, a0                      # parent cursor
	mv   s8, a2                      # parent grants remaining
.Lia_parent:
	beqz s8, .Lia_no                 # this child grant is covered by no parent grant
	mv   a0, s3
	mv   a1, s7
	call grant_subset_framed
	bnez a0, .Lia_covered
	mv   a0, s7
	call skip_value
	mv   s7, a0
	addi s8, s8, -1
	j    .Lia_parent
.Lia_covered:
	mv   a0, s3
	call skip_value
	mv   s3, a0
	addi s5, s5, -1
	j    .Lia_child
.Lia_expiry:
	# §5.6 expiration, nil-vs-finite: a child with NO expires_at is INFINITE, and infinite
	# exceeds any finite parent. The permissive reading — treat the absent child field as
	# "inherits the parent's" — is the one a reader reaches by accident and is explicitly
	# non-conformant.
	mv   a0, s2
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lia_yes                # parent never expires → nothing to bound
	call read_head
	bnez a1, .Lia_no                 # not a uint64 → unusable, never "absent"
	mv   s8, a2                      # parent expiry
	mv   a0, s1
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lia_no                 # infinite child under a finite parent
	call read_head
	bnez a1, .Lia_no
	bgtu a2, s8, .Lia_no
.Lia_yes:
	li   a0, 1
	j    .Lia_ret
.Lia_no:
	li   a0, 0
.Lia_ret:
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# caveats_ok(a0 = parent token data, a1 = child token data, a2 = depth) -> a0 = 1|0.
# §5.5 check_delegation_caveats. An absent block means there is nothing to enforce.
	.type caveats_ok, @function
caveats_ok:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s1, a1                      # child token data
	mv   s2, a2                      # depth
	adr_l a1, ka_deleg_caveats
	li   a2, 18
	call map_find                    # a0 = parent token data
	beqz a0, .Lco_yes
	mv   s3, a0                      # caveats map
	# no_delegation
	mv   a0, s3
	adr_l a1, ka_no_delegation
	li   a2, 13
	call map_find
	beqz a0, .Lco_depth
	lbu  t0, 0(a0)
	li   t1, 0xf5                    # CBOR true
	beq  t0, t1, .Lco_no
.Lco_depth:
	# max_delegation_depth — denied when depth >= limit
	mv   a0, s3
	adr_l a1, ka_max_deleg_depth
	li   a2, 20
	call map_find
	beqz a0, .Lco_ttl
	call read_head
	bnez a1, .Lco_no
	bgeu s2, a2, .Lco_no
.Lco_ttl:
	# max_delegation_ttl — an infinite child exceeds any finite limit
	mv   a0, s3
	adr_l a1, ka_max_deleg_ttl
	li   a2, 18
	call map_find
	beqz a0, .Lco_yes
	call read_head
	bnez a1, .Lco_no
	mv   s4, a2                      # limit
	mv   a0, s1
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lco_no                 # child never expires → unbounded ttl
	call read_head
	bnez a1, .Lco_no
	mv   s5, a2                      # child expires_at
	mv   a0, s1
	adr_l a1, ka_created
	li   a2, 10
	call map_find
	beqz a0, .Lco_no
	call read_head
	bnez a1, .Lco_no
	bltu s5, a2, .Lco_yes            # already expired at birth — bounded by anything
	sub  s5, s5, a2
	bgtu s5, s4, .Lco_no
.Lco_yes:
	li   a0, 1
	j    .Lco_ret
.Lco_no:
	li   a0, 0
.Lco_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# link_temporal_ok(a0 = token data) -> a0 = 1|0, against g_now (§5.5 `t`, sampled once).
#
# The CAP-6a REPRESENTABILITY test runs FIRST and is the whole point: an accessor that
# answers "nothing" for both an ABSENT field and a PRESENT-but-not-uint64 one collapses
# MALFORMED into ABSENT — and absent means "no expiry", so that reading hands an immortal
# capability to whoever sent the malformed value. Here the two are distinguishable by
# construction: map_find answers ABSENT, read_head's major answers REPRESENTABLE. CAP-6a
# covers THREE fields, and created_at is the one an audit shaped around expiry checks
# misses. (A bignum can only reach a peer as a major-type-6 tag and is refused at decode;
# what arrives here is the negative form, major type 1.)
	.type link_temporal_ok, @function
link_temporal_ok:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	mv   s1, a0
	adr_l a1, ka_created
	li   a2, 10
	call map_find
	beqz a0, .Llt_nb
	call read_head
	bnez a1, .Llt_no
.Llt_nb:
	mv   a0, s1
	adr_l a1, ka_notbefore
	li   a2, 10
	call map_find
	beqz a0, .Llt_exp
	call read_head
	bnez a1, .Llt_no
	adr_l t0, g_now
	ld   t0, 0(t0)
	bltu t0, a2, .Llt_no             # now < not_before
.Llt_exp:
	mv   a0, s1
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Llt_yes
	call read_head
	bnez a1, .Llt_no
	# §5.6 CAP-6: expiry is an EXCLUSIVE upper bound — expired when now >= expires_at. This
	# pairs with ttl_ms:0 minting expires_at == created_at, which must be expired at every
	# observable instant rather than valid for one and racing.
	adr_l t0, g_now
	ld   t0, 0(t0)
	bgeu t0, a2, .Llt_no
.Llt_yes:
	li   a0, 1
	j    .Llt_ret
.Llt_no:
	li   a0, 0
.Llt_ret:
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# =====================================================================
# verify_get_cap(a0 = exec data map) -> a0 = 0 authorized, 1 rejected (403/401 sent).
# §5.2 capability-class + §5.5 delegation-chain verification.
#
# Walks capability → parent → … → root, validating EVERY link: content-hash integrity,
# revocation, grantee resolution, temporal validity (CAP-6a representability first), and the
# granter's signature. For every non-root link it additionally checks the parent linkage
# (parent.grantee == child.granter), §5.6 attenuation under §5.5a per-link granter frames,
# and the parent's delegation caveats. The ROOT's granter must be this peer — that check has
# not gone away, it has moved to the END of the walk where it belongs instead of standing in
# for the walk. A fail-closed root-trust gate answers about ten reject-direction chain
# vectors correctly for a reason unrelated to what they test, and refuses CAP-5/CAP-6/CAP-6a
# two gates before the mint they are named after.
	.type verify_get_cap, @function
# s1=included s2=author s3=cur hash s4=depth s5=child token data (ctd) s7=this link's td
# s8=this link's granter s9=scratch s10=exec. s6 is the global CBOR cursor, untouched.
verify_get_cap:
	addi sp, sp, -96
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	sd   s9, 72(sp)
	sd   s10, 80(sp)
	mv   s0, sp
	mv   s10, a0                     # exec data map
	# capability present?
	adr_l a1, k_capability
	li   a2, 10
	call map_find
	beqz a0, .Lvgc_403
	call get_text                    # a0 = cap_hash ptr, a2 = len
	li   t0, 33
	bne  a2, t0, .Lvgc_403
	mv   s3, a0                      # cur = the presented capability hash
	# author (verify_get_auth already ensured present)
	mv   a0, s10
	adr_l a1, k_author
	li   a2, 6
	call map_find
	beqz a0, .Lvgc_403
	call get_text
	mv   s2, a0                      # author ptr
	# included
	adr_l a0, b_req
	adr_l a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lvgc_403
	mv   s1, a0                      # included
	li   s4, 0                       # depth
	li   s5, 0                       # child token data (none yet)
	# §5.5 v7.76: `t` is sampled ONCE per verdict and never re-sampled per link — otherwise
	# the verdict depends on wall-clock drift within a single walk.
	call now_ms
	adr_l t0, g_now
	sd   a0, 0(t0)
# ---------------------------------------------------------------- the walk
.Lvgc_walk:
	mv   a0, s1
	mv   a1, s3
	call included_find_by_key
	beqz a0, .Lvgc_403               # capability_not_in_included
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvgc_403
	mv   s7, a0                      # td — this link's token data map
	# integrity: the link's data must hash to the hash we followed to reach it. A token whose
	# bytes were altered after signing no longer hashes to its key → 403.
	call skip_value
	sub  a3, a0, s7                  # data byte length (arg4)
	adr_l a0, ta_token
	li   a1, 23
	mv   a2, s7
	adr_l a4, g_link_ch
	call ec_content_hash
	adr_l a0, g_link_ch
	mv   a1, s3
	li   a2, 33
	call memeq
	beqz a0, .Lvgc_403               # recomputed hash ≠ the key we followed → substituted
	# §6.9a — revocation is PER LINK: revoking an intermediate kills everything under it.
	mv   a0, s3
	call is_revoked
	bnez a0, .Lvgc_403
	# grantee present, 33 bytes, and resolving to a present system/peer — per link, not just
	# at the leaf. An unresolvable grantee is the §5.2 / PR-3 single-401 carve-out, NOT 403.
	mv   a0, s7
	adr_l a1, ka_grantee
	li   a2, 7
	call map_find
	beqz a0, .Lvgc_403
	call get_text
	li   t0, 33
	bne  a2, t0, .Lvgc_403
	mv   s8, a0                      # grantee ptr (s8 becomes the granter below)
	mv   a0, s1
	mv   a1, s8
	call included_find_by_key
	beqz a0, .Lvgc_grantee_401
	adr_l a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Lvgc_grantee_401
	call get_text
	li   t0, 11
	bne  a2, t0, .Lvgc_grantee_401
	adr_l a1, ta_peer
	li   a2, 11
	call memeq
	beqz a0, .Lvgc_grantee_401
	# linkage: the LEAF is granted to the request author; every parent is granted to the
	# granter of the link below it (g_pgee carries that hash across the hop).
	mv   a0, s8
	beqz s4, .Lvgc_link_leaf
	adr_l a1, g_pgee
	j    .Lvgc_link_cmp
.Lvgc_link_leaf:
	mv   a1, s2                      # author
.Lvgc_link_cmp:
	li   a2, 33
	call memeq
	beqz a0, .Lvgc_403               # grantee_author_mismatch / broken chain linkage
	# temporal validity of THIS link (CAP-6a representability first)
	mv   a0, s7
	call link_temporal_ok
	beqz a0, .Lvgc_403
	# granter
	mv   a0, s7
	adr_l a1, ka_granter
	li   a2, 7
	call map_find
	beqz a0, .Lvgc_403
	mv   s8, a0                      # granter value ptr
	call read_head                   # a1 = major type
	li   t0, 5
	bne  a1, t0, .Lvgc_single_granter
	# §3.6 K-of-N multi-granter. M3 structural validity runs BEFORE any signature check, so a
	# violation surfaces as 403 capability_denied rather than as a signature failure.
	# Multi-sig is ROOT-ONLY: a multi-granter link carrying a parent is structurally invalid.
	mv   a0, s7
	adr_l a1, ka_parent
	li   a2, 6
	call map_find
	beqz a0, .Lvgc_ms_root
	lbu  t0, 0(a0)                   # CBOR null is "no parent"
	li   t1, 0xf6
	bne  t0, t1, .Lvgc_403
.Lvgc_ms_root:
	# A quorum root has no single granter peer_id, so §5.5a has no frame to canonicalize its
	# resource patterns against. Rather than invent one, a K-of-N root is accepted only when
	# it is the capability actually PRESENTED (depth 0), where no attenuation comparison is
	# needed. A chain whose ROOT is K-of-N is refused, and that limit is written here rather
	# than left to be discovered.
	bnez s4, .Lvgc_403
	mv   a0, s8
	mv   a1, s3
	mv   a2, s1
	call verify_multisig_granter
	bnez a0, .Lvgc_403
	j    .Lvgc_ok                    # quorum met — the chain terminates here
.Lvgc_single_granter:
	mv   a0, s8
	call get_text
	li   t0, 33
	bne  a2, t0, .Lvgc_403
	mv   s8, a0                      # granter hash
	# signature over THIS link, by THIS link's granter
	mv   a0, s1
	mv   a1, s8
	call included_find_by_key
	beqz a0, .Lvgc_403
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvgc_403
	adr_l a1, ka_pubkey
	li   a2, 10
	call map_find
	beqz a0, .Lvgc_403
	call get_text
	mv   s9, a0                      # granter pubkey (survives find_req_sig)
	mv   a0, s1
	mv   a1, s8
	mv   a2, s3
	call find_req_sig                # a0 = 64-byte sig ptr | 0
	beqz a0, .Lvgc_403               # unsigned / forged
	mv   a3, a0
	mv   a0, s9
	mv   a1, s3
	li   a2, 33
	call ec_ed25519_verify
	bnez a0, .Lvgc_403
	# this link's §5.5a frame = its granter's peer_id
	mv   a0, s1
	mv   a1, s8
	adr_l a2, g_pfr
	adr_l a3, g_pfrlen
	call peerid_of
	beqz a0, .Lvgc_403
	# attenuation + caveats against the child we arrived from
	beqz s4, .Lvgc_rootcheck
	mv   a0, s5                      # ctd
	mv   a1, s7
	call is_attenuated
	beqz a0, .Lvgc_403
	mv   a0, s7
	mv   a1, s5
	addi a2, s4, -1
	call caveats_ok
	beqz a0, .Lvgc_403
.Lvgc_rootcheck:
	mv   a0, s7
	adr_l a1, ka_parent
	li   a2, 6
	call map_find
	beqz a0, .Lvgc_root
	lbu  t0, 0(a0)                   # an explicit null parent is a root
	li   t1, 0xf6
	beq  t0, t1, .Lvgc_root
	mv   s9, a0                      # parent hash value ptr
	# carry the child state across the hop: its data, its granter, and its frame
	mv   s5, s7                      # ctd = this link
	adr_l a0, g_pgee
	mv   a1, s8
	li   a2, 33
	call mcpy
	adr_l a0, g_cfr
	adr_l a1, g_pfr
	li   a2, 128
	call mcpy
	adr_l t0, g_pfrlen
	ld   t0, 0(t0)
	adr_l t1, g_cfrlen
	sd   t0, 0(t1)
	mv   a0, s9
	call get_text
	li   t0, 33
	bne  a2, t0, .Lvgc_403
	mv   s3, a0                      # cur = parent
	addi s4, s4, 1
	# §5.5 collect_authority_chain bounds depth at 64. chain_depth_check already answers 400
	# chain_depth_exceeded ahead of this walk, so this is the belt to that braces — it exists
	# so the loop cannot run unbounded if the walk is ever reached by another path.
	li   t0, 64
	bgtu s4, t0, .Lvgc_403
	j    .Lvgc_walk
.Lvgc_root:
	# §5.5 root trust: the chain must terminate at a capability THIS peer granted. The check
	# has not gone away — it is here, at the end of the walk, instead of standing in for it.
	mv   a0, s8
	adr_l a1, g_identity_hash
	li   a2, 33
	call memeq
	beqz a0, .Lvgc_403
.Lvgc_ok:
	li   a0, 0                       # authorized
	j    .Lvgc_ret
.Lvgc_403:
	li   a0, 403
	adr_l a1, ec_cap_denied
	call send_error
	li   a0, 1
	j    .Lvgc_ret
.Lvgc_grantee_401:
	li   a0, 401
	adr_l a1, ec_unresolvable_grantee
	call send_error
	li   a0, 1
.Lvgc_ret:
	ld   s10, 80(sp)
	ld   s9, 72(sp)
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 96
	ret

# =====================================================================
# is_peer_id(a0 = ptr, a1 = len) -> a0 = 1 if len >= 46 and every byte is in the Base58
# alphabet (§5.4 is_peer_id: Base58(key_type||hash_type||digest), 46 chars is the minimum
# for the smallest supported algorithm — Ed25519+SHA-256), else 0. Used by extract_peer
# (derive_handler below) to decide whether a uri's first path segment is a real peer id.
# Ported from asm-arm64/src/dispatch.s (x0/x1/x9/x19/x20/x21 -> a0/a1/t0/s1/s2/s3).
	.globl is_peer_id
	.type is_peer_id, @function
is_peer_id:
	li   t0, 46
	bltu a1, t0, .Lipi_no
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a0                      # ptr
	mv   s2, a1                      # len
	li   s3, 0                       # i
.Lipi_loop:
	bgeu s3, s2, .Lipi_yes
	add  t0, s1, s3
	lbu  t0, 0(t0)
	adr_l t1, s_base58_alpha
	li   t2, 0
.Lipi_scan:
	li   t3, 58
	bgeu t2, t3, .Lipi_no_pop
	add  t4, t1, t2
	lbu  t4, 0(t4)
	beq  t4, t0, .Lipi_found
	addi t2, t2, 1
	j    .Lipi_scan
.Lipi_found:
	addi s3, s3, 1
	j    .Lipi_loop
.Lipi_no_pop:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	li   a0, 0
	ret
.Lipi_yes:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	li   a0, 1
	ret
.Lipi_no:
	li   a0, 0
	ret

# =====================================================================
# derive_handler(a0 = exec data map) — set g_handler_ptr/g_handler_len to the request's
# target handler, parsed from data.uri by stripping the "entity://<peer_id>/" prefix (scheme
# + authority). Falls back to system/tree when uri is absent or lacks the scheme, so the
# get path (uri = entity://<peer>/system/tree) and unrouted ops both scope-check the real
# handler namespace instead of a hardcoded one. Closes handler_scope_denied.
# Also sets g_target_peer_ptr/g_target_peer_len (§5.2 extract_peer, F-peers): the uri's first
# path segment when it validates as a real peer id (is_peer_id above), else the default —
# this peer's own g_peerid/g_peerid_len — exactly extract_peer's local-peer fallback. Every
# early-return path below leaves that default in place, matching extract_peer's short-form/
# no-scheme/no-slash cases (all of which mean "no peer prefix" -> local peer).
	.globl derive_handler
	.type derive_handler, @function
derive_handler:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)                 # s1=cursor(rbx), s2=uri ptr(r12)
	sd   s2, 24(sp)
	sd   s3, 32(sp)               # s3=uri len/remaining(r13)
	sd   s4, 40(sp)               # s4=segment start(r14)
	mv   s0, sp
	adr_l t0, va_systree            # default handler = system/tree
	adr_l t1, g_handler_ptr
	sd   t0, 0(t1)
	li   t0, 11
	adr_l t1, g_handler_len
	sd   t0, 0(t1)
	adr_l t0, g_peerid              # default target_peer = local peer id
	adr_l t1, g_target_peer_ptr
	sd   t0, 0(t1)
	adr_l t0, g_peerid_len
	ld   t0, 0(t0)
	adr_l t1, g_target_peer_len
	sd   t0, 0(t1)
	# a0 = exec (preserved into map_find)
	adr_l a1, k_uri
	li   a2, 3
	call map_find                   # a0 = exec (preserved)
	beqz a0, .Ldh_ret
	call get_text                   # a0 = uri ptr, a2 = uri len
	mv   s2, a0
	mv   s3, a2
	li   t0, 9                      # "entity://" = 9 bytes
	bltu s3, t0, .Ldh_ret
	mv   a0, s2
	adr_l a1, s_entity_scheme
	li   a2, 9
	call memeq
	beqz a0, .Ldh_ret
	addi s1, s2, 9                  # cursor past the scheme
	mv   s4, s1                     # first-segment start (candidate target_peer)
	addi s3, s3, -9               # remaining len (the "<peer>/<handler>" authority+path)
.Ldh_scan:
	beqz s3, .Ldh_ret              # no '/', keep defaults (handler + target_peer)
	lbu  t0, 0(s1)
	li   t1, 0x2f
	beq  t0, t1, .Ldh_found
	addi s1, s1, 1
	addi s3, s3, -1
	j    .Ldh_scan
.Ldh_found:
	# candidate peer-id segment = [s4, s1) — validate before adopting it as target_peer
	# (extract_peer only trusts a first segment that is_peer_id).
	sub  a1, s1, s4                 # segment length
	mv   a0, s4
	call is_peer_id
	beqz a0, .Ldh_not_peer
	adr_l t0, g_target_peer_ptr
	sd   s4, 0(t0)
	sub  t0, s1, s4
	adr_l t1, g_target_peer_len
	sd   t0, 0(t1)
.Ldh_not_peer:
	addi s1, s1, 1                  # skip the '/'
	addi s3, s3, -1
	adr_l t0, g_handler_ptr
	sd   s1, 0(t0)
	adr_l t0, g_handler_len
	sd   s3, 0(t0)
.Ldh_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# =====================================================================
# uri_targets_local(a0 = exec data map) -> a0 = 0 local / 1 foreign (400 already sent).
#
# §1.4 / §6.5 step 3 — the ADDRESS gate, and it is the companion of derive_handler directly
# above: that routine strips "entity://<peer_id>/" UNCONDITIONALLY, which IS the bug. §6.5
# step 3 forbids exactly that route — drop a FOREIGN peer id, resolve OUR handler at the
# remaining path, and let §5.2 Dimension 4 decide — because the presented grant's `peers`
# scope then authorizes a foreign namespace. Measured before this gate: status 200, the live
# foreign-namespace privilege escalation.
#
# The refusal is on the ADDRESS, so it is 400 invalid_request and never 403/404: a 404 would
# assert "this peer has no such handler", which is false of a peer that HAS it and is
# refusing the address, and a 403 would make it an authz verdict when no capability question
# was asked. Called from `dispatch` before the op ladder — i.e. before this peer resolves
# anything — since the ladder is where an asm peer's handler resolution actually happens.
#
# This is a VALUE comparison (two byte strings), not a flag test, so it ports to RISC-V
# unchanged — unlike the §5.6 rule-3 overflow check, which had to be restated because this
# ISA has no condition-flags register.
#
# derive_handler defaults g_target_peer_* to our own peer id whenever the uri is absent,
# carries no "entity://" scheme, or has no peer-id-shaped first segment, so every one of
# those passes the gate untouched — hello/authenticate carry no uri and are unaffected.
	.type uri_targets_local, @function
uri_targets_local:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	call derive_handler             # a0 = exec (→ g_target_peer_ptr/len)
	adr_l t0, g_target_peer_len
	ld   t1, 0(t0)
	adr_l t0, g_peerid_len
	ld   t0, 0(t0)
	bne  t1, t0, .Lutl_foreign      # lengths differ → not us
	mv   a2, t0
	adr_l t0, g_target_peer_ptr
	ld   a0, 0(t0)
	adr_l a1, g_peerid
	call memeq
	beqz a0, .Lutl_foreign
	li   a0, 0                      # local
	j    .Lutl_ret
.Lutl_foreign:
	li   a0, 400
	adr_l a1, ec_invalid_request
	call send_error
	li   a0, 1
.Lutl_ret:
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret
# =====================================================================
# verify_get_scope(a0 = exec data map) -> a0 = 0 authorized, 1 rejected (403 sent).
# §5.2 grant-scope stage, after verify_get_cap: the presented token must carry a grant that
# permits (operation, handler [from uri], resource-target). No matching grant → 403
# capability_denied (default-deny).
	.type verify_get_scope, @function
# s5=exec, s1=cap hash, s4=token data map, s3=now.
verify_get_scope:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s5, a0                     # exec
	# derive the request's handler namespace from data.uri (→ g_handler_ptr/len).
	mv   a0, s5                     # exec
	call derive_handler
	# capability → token → token data map
	mv   a0, s5
	adr_l a1, k_capability
	li   a2, 10
	call map_find
	beqz a0, .Lvgsc_ok               # (verify_get_cap already enforced presence)
	call get_text
	mv   s1, a0                     # cap hash
	adr_l a0, b_req
	adr_l a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lvgsc_ok
	mv   a1, s1
	call included_find_by_key
	beqz a0, .Lvgsc_ok
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvgsc_ok
	mv   s4, a0                     # token data map
	# ---- §5.5a frame for the DISPATCH surface: the presented cap's own granter ----
	# Derived here rather than assumed to be the local peer — they are byte-identical for
	# every self-issued capability, which is exactly why framing against the verifier stays
	# latent until a foreign-granted cap arrives.
	mv   a0, s4
	adr_l a1, ka_granter
	li   a2, 7
	call map_find
	beqz a0, .Lvgsc_403
	mv   s2, a0
	call read_head                  # a1 = major type
	li   t0, 5
	bne  a1, t0, .Lvgsc_single_frame
	# §3.6 K-of-N root: there is no single granter, so §5.5a has no granter peer_id to frame
	# against. The local peer is the CORRECT frame here and not a fallback — M6 already
	# required that the local peer be in the signer set AND have signed, and §5.5 says a
	# quorum cap's "subsequent use is locally rooted". The quorum authorized issuance; the
	# namespace its patterns name is this peer's.
	adr_l t0, g_peerid_len
	ld   a2, 0(t0)
	adr_l t0, g_dfrlen
	sd   a2, 0(t0)
	adr_l a0, g_dfr
	adr_l a1, g_peerid
	call mcpy
	j    .Lvgsc_frame_ok
.Lvgsc_single_frame:
	mv   a0, s2
	call get_text
	mv   s2, a0                     # granter hash
	adr_l a0, b_req
	adr_l a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lvgsc_403
	mv   a1, s2
	adr_l a2, g_dfr
	adr_l a3, g_dfrlen
	call peerid_of
	beqz a0, .Lvgsc_403
.Lvgsc_frame_ok:
	# ---- token temporal validity (only fires if the fields are present) ----
	call now_ms                      # a0 = wall-clock ms
	mv   s3, a0                     # now
	# expires_at present and now > it → expired
	mv   a0, s4
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lvgsc_nb
	call read_head                   # a2 = expires_at (uint ms)
	bgtu s3, a2, .Lvgsc_403          # now > expires_at
.Lvgsc_nb:
	# not_before present and now < it → not yet valid
	mv   a0, s4
	adr_l a1, ka_notbefore
	li   a2, 10
	call map_find
	beqz a0, .Lvgsc_temporal_ok
	call read_head                   # a2 = not_before (uint ms)
	bltu s3, a2, .Lvgsc_403          # now < not_before
.Lvgsc_temporal_ok:
	# operation
	mv   a0, s5
	adr_l a1, k_op
	li   a2, 9
	call map_find
	beqz a0, .Lvgsc_403
	call get_text
	mv   s2, a0                     # op ptr
	mv   s1, a2                     # op len
	# target = resource.targets[0]
	mv   a0, s5
	adr_l a1, k_resource
	li   a2, 8
	call map_find
	beqz a0, .Lvgsc_403
	adr_l a1, k_targets
	li   a2, 7
	call map_find
	beqz a0, .Lvgsc_403
	call read_head                   # array head: a2=count
	beqz a2, .Lvgsc_403
	call get_text                    # a0=target ptr, a2=target len
	# grant_scope_ok(token_data, target ptr, target len, op ptr, op len)
	mv   a1, a0                      # target ptr
	mv   a0, s4                      # token data
	# a2 already = target len
	mv   a3, s2                      # op ptr
	mv   a4, s1                      # op len
	call grant_scope_ok
	bnez a0, .Lvgsc_ok
.Lvgsc_403:
	li   a0, 403
	adr_l a1, ec_cap_denied
	call send_error
	li   a0, 1
	j    .Lvgsc_ret
.Lvgsc_ok:
	li   a0, 0
.Lvgsc_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# =====================================================================
# grant_scope_ok(a0=token data map, a1=target ptr, a2=target len, a3=op ptr, a4=op len)
#   -> a0 = 1 if some grant permits (operation ∈ operations.include) ∧ (handler ∈
#      handlers.include) ∧ (target matches resources.include), else 0. "*" wildcards honored.
# The handler is g_handler_ptr/len, parsed from data.uri by derive_handler.
	.globl grant_scope_ok
	.type grant_scope_ok, @function
# s4=target ptr, s5=target len, s6 is the global cursor (untouched), s7=op ptr,
# s8=op len, s3=cursor(grant map ptr), s1=grant count. (r12→s2, r13→s4, r14→s5,
# r15→s7, rbp→s8, rbx→s1 — chosen to avoid the s6 writer cursor.)
grant_scope_ok:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	mv   s0, sp
	mv   s4, a1                      # target ptr
	mv   s5, a2                      # target len
	mv   s7, a3                      # op ptr
	mv   s8, a4                      # op len
	# grants = map_find(token_data, "grants", 6)
	adr_l a1, ka_grants
	li   a2, 6
	call map_find                    # a0 = token data (still) map_find(a0,...)
	beqz a0, .Lgs_no
	call read_head                   # a0=first elem, a1=4, a2=count
	mv   s2, a0                      # cursor (grant map ptr)
	mv   s1, a2                      # grant count
.Lgs_loop:
	beqz s1, .Lgs_no
	# operations.include ∋ op ?
	mv   a0, s2
	adr_l a1, ka_operations
	li   a2, 10
	call map_find
	beqz a0, .Lgs_next
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lgs_next
	mv   a1, s7                      # op ptr
	mv   a2, s8                      # op len
	call array_contains_star
	beqz a0, .Lgs_next
	# handlers.include ∋ system/tree ?
	mv   a0, s2
	adr_l a1, ka_handlers
	li   a2, 8
	call map_find
	beqz a0, .Lgs_next
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lgs_next
	adr_l t0, g_handler_ptr          # request handler (parsed from data.uri)
	ld   a1, 0(t0)
	adr_l t0, g_handler_len
	ld   a2, 0(t0)
	call array_contains_star
	beqz a0, .Lgs_next
	# peers.include ∋ target_peer ? (§5.2/F-peers) grant.peers defaults to
	# {include:[local_peer_id]} when the grant omits the field entirely.
	mv   a0, s2
	adr_l a1, ka_peers
	li   a2, 5
	call map_find
	beqz a0, .Lgs_peers_default
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lgs_peers_default
	adr_l t0, g_target_peer_ptr
	ld   a1, 0(t0)
	adr_l t0, g_target_peer_len
	ld   a2, 0(t0)
	call array_contains_star
	beqz a0, .Lgs_next
	j    .Lgs_peers_ok
.Lgs_peers_default:
	adr_l t0, g_target_peer_len
	ld   t1, 0(t0)                   # target_peer len
	adr_l t0, g_peerid_len
	ld   t0, 0(t0)                   # local peer id len
	bne  t1, t0, .Lgs_next
	adr_l a0, g_target_peer_ptr
	ld   a0, 0(a0)                   # target_peer ptr
	adr_l a1, g_peerid               # local peer id ptr (inline buffer, not a pointer slot)
	mv   a2, t0                      # len (shared)
	call memeq
	beqz a0, .Lgs_next
.Lgs_peers_ok:
	# resources.include matches target ?
	mv   a0, s2
	adr_l a1, ka_resources
	li   a2, 9
	call map_find
	beqz a0, .Lgs_next
	adr_l a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lgs_next
	mv   a1, s4                      # target ptr
	mv   a2, s5                      # target len
	call resources_cover_target
	bnez a0, .Lgs_yes
.Lgs_next:
	mv   a0, s2
	call skip_value                  # advance past this grant map
	mv   s2, a0
	addi s1, s1, -1
	j    .Lgs_loop
.Lgs_yes:
	li   a0, 1
	j    .Lgs_ret
.Lgs_no:
	li   a0, 0
.Lgs_ret:
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# op_scope_ok(a0 = token data, a1 = op ptr, a2 = op len) -> a0 = 1 if some grant permits
# (operation ∈ operations.include) ∧ (handler ∈ handlers.include) ∧ (target peer ∈ peers).
# The RESOURCE dimension is absent by construction: these are the capability-vocabulary ops
# that carry no resource.targets, so there is no target to match and asking for one would
# deny every one of them.
	.type op_scope_ok, @function
op_scope_ok:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s3, a1                      # op ptr
	mv   s4, a2                      # op len
	adr_l a1, ka_grants
	li   a2, 6
	call map_find
	beqz a0, .Los_no
	call read_head
	li   t0, 4
	bne  a1, t0, .Los_no
	mv   s2, a0                      # grant cursor
	mv   s1, a2                      # grant count
.Los_loop:
	beqz s1, .Los_no
	mv   a0, s2
	adr_l a1, ka_operations
	li   a2, 10
	call get_include
	beqz a0, .Los_next
	mv   a1, s3
	mv   a2, s4
	call array_contains_star
	beqz a0, .Los_next
	mv   a0, s2
	adr_l a1, ka_handlers
	li   a2, 8
	call get_include
	beqz a0, .Los_next
	adr_l t0, g_handler_ptr
	ld   a1, 0(t0)
	adr_l t0, g_handler_len
	ld   a2, 0(t0)
	call array_contains_star
	beqz a0, .Los_next
	mv   a0, s2
	adr_l a1, ka_peers
	li   a2, 5
	call get_include
	beqz a0, .Los_peers_default
	adr_l t0, g_target_peer_ptr
	ld   a1, 0(t0)
	adr_l t0, g_target_peer_len
	ld   a2, 0(t0)
	call array_contains_star
	beqz a0, .Los_next
	j    .Los_yes
.Los_peers_default:
	adr_l t0, g_target_peer_len
	ld   t1, 0(t0)
	adr_l t0, g_peerid_len
	ld   t0, 0(t0)
	bne  t1, t0, .Los_next
	mv   a2, t0
	adr_l t0, g_target_peer_ptr
	ld   a0, 0(t0)
	adr_l a1, g_peerid
	call memeq
	beqz a0, .Los_next
	j    .Los_yes
.Los_next:
	mv   a0, s2
	call skip_value
	mv   s2, a0
	addi s1, s1, -1
	j    .Los_loop
.Los_yes:
	li   a0, 1
	j    .Los_ret
.Los_no:
	li   a0, 0
.Los_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# verify_op_scope(a0 = exec data map) -> a0 = 0 authorized, 1 rejected (403 sent).
# §5.2 operation-scope gate for a capability-vocabulary op with no resource.targets. Without
# it a peer that authenticates a caller then routes straight into the handler never asks
# whether the presented capability covers this op on this handler at all — and a floor cap
# (capability:request only) would reach configure/revoke unchecked.
	.type verify_op_scope, @function
verify_op_scope:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s4, a0                      # exec
	call derive_handler              # a0 = exec (→ g_handler_ptr/len, g_target_peer_*)
	mv   a0, s4
	adr_l a1, k_capability
	li   a2, 10
	call map_find
	beqz a0, .Lvos_403
	call get_text
	mv   s1, a0                      # cap hash
	adr_l a0, b_req
	adr_l a1, ka_included
	li   a2, 8
	call map_find
	beqz a0, .Lvos_403
	mv   a1, s1
	call included_find_by_key
	beqz a0, .Lvos_403
	adr_l a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lvos_403
	mv   s3, a0                      # token data
	call now_ms
	mv   s2, a0                      # now
	mv   a0, s3
	adr_l a1, ka_expires
	li   a2, 10
	call map_find
	beqz a0, .Lvos_nb
	call read_head
	bgtu s2, a2, .Lvos_403           # now > expires_at
.Lvos_nb:
	mv   a0, s3
	adr_l a1, ka_notbefore
	li   a2, 10
	call map_find
	beqz a0, .Lvos_op
	call read_head
	bltu s2, a2, .Lvos_403           # now < not_before
.Lvos_op:
	mv   a0, s4
	adr_l a1, k_op
	li   a2, 9
	call map_find
	beqz a0, .Lvos_403
	call get_text
	mv   a1, a0                      # op ptr
	mv   a0, s3                      # token data
	# a2 already = op len
	call op_scope_ok
	bnez a0, .Lvos_ok
.Lvos_403:
	li   a0, 403
	adr_l a1, ec_cap_denied
	call send_error
	li   a0, 1
	j    .Lvos_ret
.Lvos_ok:
	li   a0, 0
.Lvos_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# resources_cover_target(a0 = resources.include array, a1 = target ptr, a2 = target len)
#   -> a0 = 1 if some pattern covers the request target under §5.5a.
#
# §5.5a surface 1, the DISPATCH boundary. The two sides canonicalize against DIFFERENT
# frames, and that asymmetry is the rule: a cap's resource patterns are the GRANTER's to
# write, so they canonicalize against the granter's peer_id (g_dfr, derived in
# verify_get_scope); the request target is a path into THIS peer's namespace, so it
# canonicalizes against the local peer_id. Frame both against the local peer and a
# foreign-granted bare "*" silently becomes "/{verifier}/*" and authorizes the verifier's
# own namespace — which is what captok_form_dispatch_minted_pl_presented_xpeer exists to
# catch, and which stays invisible for as long as the peer refuses foreign-granted caps
# outright (a vacuous pass that the chain walk converts into a real one).
	.type resources_cover_target, @function
resources_cover_target:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	mv   s0, sp
	mv   s1, a0                      # include array
	mv   a0, a1
	mv   a1, a2
	adr_l a2, g_peerid
	adr_l t0, g_peerid_len
	ld   a3, 0(t0)
	adr_l a4, b_canon_a
	call canon
	mv   s2, a0                      # canonical target length
	mv   a0, s1
	call read_head
	li   t0, 4
	bne  a1, t0, .Lrct_no
	mv   s3, a0                      # pattern cursor
	mv   s4, a2                      # remaining
.Lrct_loop:
	beqz s4, .Lrct_no
	mv   a0, s3
	call read_head                   # a0 = pattern bytes, a2 = len
	mv   s5, a0
	mv   s7, a2
	add  s3, a0, a2
	addi s4, s4, -1
	mv   a0, s5
	mv   a1, s7
	adr_l a2, g_dfr
	adr_l t0, g_dfrlen
	ld   a3, 0(t0)
	adr_l a4, b_canon_b
	call canon
	mv   a3, a0
	adr_l a0, b_canon_a
	mv   a1, s2
	adr_l a2, b_canon_b
	call pat_covers
	beqz a0, .Lrct_loop
	li   a0, 1
	j    .Lrct_ret
.Lrct_no:
	li   a0, 0
.Lrct_ret:
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# array_contains_star(a0=array, a1=needle, a2=needle len) -> a0 = 1 if the array
# contains the needle OR a bare "*". Reuses array_contains twice.
	.type array_contains_star, @function
# s2=array, s3=needle, s4=needle len.
array_contains_star:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	mv   s0, sp
	mv   s2, a0                     # array
	mv   s3, a1                     # needle
	mv   s4, a2                     # needle len
	call array_contains            # (a0=array, a1=needle, a2=len)
	bnez a0, .Lacs_yes
	mv   a0, s2
	lla  a1, s_star
	li   a2, 1
	call array_contains
	bnez a0, .Lacs_yes
	li   a0, 0
	j    .Lacs_ret
.Lacs_yes:
	li   a0, 1
.Lacs_ret:
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# resource_matches(a0=include array, a1=target ptr, a2=target len) -> a0 = 1 if any
# pattern matches. Patterns: bare "*" (any); trailing "/*" (prefix match on everything up to
# and including the slash); otherwise an exact match.
	.type resource_matches, @function
# s4=target ptr, s5=target len, s2=cursor, s1=pattern count, s7=pattern ptr,
# s8=pattern len.
resource_matches:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	sd   s8, 64(sp)
	mv   s0, sp
	mv   s4, a1                     # target ptr
	mv   s5, a2                     # target len
	call read_head                  # a0=array → a0=first elem, a2=count
	mv   s2, a0                     # cursor
	mv   s1, a2                     # pattern count
.Lrm_l:
	beqz s1, .Lrm_no
	mv   a0, s2
	call read_head                  # pattern text: a0=ptr, a2=len
	mv   s7, a0                     # pattern ptr
	mv   s8, a2                     # pattern len
	add  s2, a0, a2                 # advance cursor past pattern
	addi s1, s1, -1
	# case bare "*"
	li   t0, 1
	bne  s8, t0, .Lrm_check_suffix
	lbu  t0, 0(s7)
	li   t1, 0x2a
	beq  t0, t1, .Lrm_yes
	j    .Lrm_l
.Lrm_check_suffix:
	# trailing "/*" ? (plen>=2 and last two bytes are '/','*')
	li   t0, 2
	bltu s8, t0, .Lrm_exact
	add  t1, s7, s8
	lbu  t0, -1(t1)                 # pattern[plen-1]
	li   t2, 0x2a
	bne  t0, t2, .Lrm_exact
	lbu  t0, -2(t1)                 # pattern[plen-2]
	li   t2, 0x2f
	bne  t0, t2, .Lrm_exact
	# prefix = pattern[0 .. plen-1] (through the slash, i.e. plen-1 bytes); target must be
	# at least that long and share the prefix bytes.
	addi t0, s8, -1                 # prefix len (keep the '/')
	bltu s5, t0, .Lrm_l             # target shorter than prefix → no match
	mv   a0, s7                     # pattern
	mv   a1, s4                     # target
	mv   a2, t0                     # prefix len → memeq len (a2)
	call memeq
	bnez a0, .Lrm_yes
	j    .Lrm_l
.Lrm_exact:
	bne  s5, s8, .Lrm_l
	mv   a0, s7                     # pattern
	mv   a1, s4                     # target
	mv   a2, s8                     # len → a2
	call memeq
	bnez a0, .Lrm_yes
	j    .Lrm_l
.Lrm_yes:
	li   a0, 1
	j    .Lrm_ret
.Lrm_no:
	li   a0, 0
.Lrm_ret:
	ld   s8, 64(sp)
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# get_include(a0 = grant map, a1 = field cstr, a2 = field len) -> a0 = <field>.include
# array value ptr | 0.  grant[field]["include"].
	.type get_include, @function
get_include:
	addi sp, sp, -16
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	mv   s0, sp
	call map_find
	beqz a0, .Lgi_no
	lla  a1, ka_include
	li   a2, 7
	call map_find
	beqz a0, .Lgi_no
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret
.Lgi_no:
	li   a0, 0
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 16
	ret

# array_subset_star(a0 = req array value, a1 = caller array value) -> a0 = 1 if every
# text element of req appears in caller (a bare "*" in caller matches any element). An empty
# req array is a vacuous subset (1).
	.type array_subset_star, @function
# s7=caller array value, s2=cursor, s1=remaining count, s4=elem ptr, s5=elem len.
array_subset_star:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	sd   s7, 48(sp)
	mv   s0, sp
	mv   s7, a1                     # caller array value
	call read_head                  # a0 = req array → a0=first elem, a2=count
	mv   s2, a0                     # cursor
	mv   s1, a2                     # remaining count
.Lss_loop:
	beqz s1, .Lss_yes
	mv   a0, s2
	call read_head                  # element text: a0=ptr, a2=len
	mv   s4, a0                     # elem ptr
	mv   s5, a2                     # elem len
	add  s2, a0, a2                 # advance cursor past this element
	addi s1, s1, -1
	mv   a0, s7                     # caller array
	mv   a1, s4
	mv   a2, s5
	call array_contains_star
	bnez a0, .Lss_loop              # covered → next req element
	li   a0, 0                      # some element not covered → not a subset
	j    .Lss_ret
.Lss_yes:
	li   a0, 1
.Lss_ret:
	ld   s7, 48(sp)
	ld   s5, 40(sp)
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# resources_subset(a0 = req resources.include, a1 = caller resources.include) -> a0 = 1 if
# every req resource is matched by a caller pattern (resource_matches: "*", trailing "/*",
# exact). Empty req → 1.
	.type resources_subset, @function
# s7=caller resources array, s2=cursor, s1=count, s4=res ptr, s5=res len.
resources_subset:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	sd   s7, 48(sp)
	mv   s0, sp
	mv   s7, a1                     # caller resources array
	call read_head                  # a0 = req array → a0=first, a2=count
	mv   s2, a0
	mv   s1, a2
.Lrs_loop:
	beqz s1, .Lrs_yes
	mv   a0, s2
	call read_head                  # req resource text: a0=ptr, a2=len
	mv   s4, a0
	mv   s5, a2
	add  s2, a0, a2
	addi s1, s1, -1
	mv   a0, s7                     # caller resources array
	mv   a1, s4
	mv   a2, s5
	call resource_matches
	bnez a0, .Lrs_loop
	li   a0, 0
	j    .Lrs_ret
.Lrs_yes:
	li   a0, 1
.Lrs_ret:
	ld   s7, 48(sp)
	ld   s5, 40(sp)
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# grant_covers(a0 = caller grant map, a1 = req grant map) -> a0 = 1 if the caller grant
# authorizes everything the req grant asks for: req.operations ⊆ caller.operations,
# req.handlers ⊆ caller.handlers, req.resources all matched by caller.resources.
	.type grant_covers, @function
# s2=caller grant, s4=req grant, s1=req.<field> include (scratch across get_include).
grant_covers:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	mv   s0, sp
	mv   s2, a0                     # caller grant
	mv   s4, a1                     # req grant
	# operations
	mv   a0, s4
	lla  a1, ka_operations
	li   a2, 10
	call get_include
	beqz a0, .Lgc_no                # req without operations.include → treat as uncoverable
	mv   s1, a0                     # req.ops
	mv   a0, s2
	lla  a1, ka_operations
	li   a2, 10
	call get_include
	beqz a0, .Lgc_no
	mv   a1, a0                     # caller.ops
	mv   a0, s1                     # req.ops
	call array_subset_star
	beqz a0, .Lgc_no
	# handlers
	mv   a0, s4
	lla  a1, ka_handlers
	li   a2, 8
	call get_include
	beqz a0, .Lgc_no
	mv   s1, a0
	mv   a0, s2
	lla  a1, ka_handlers
	li   a2, 8
	call get_include
	beqz a0, .Lgc_no
	mv   a1, a0
	mv   a0, s1
	call array_subset_star
	beqz a0, .Lgc_no
	# resources (req resources ⊆ caller resources by pattern match); absent req resources → ok
	mv   a0, s4
	lla  a1, ka_resources
	li   a2, 9
	call get_include
	beqz a0, .Lgc_yes               # no resources requested → nothing to bound
	mv   s1, a0
	mv   a0, s2
	lla  a1, ka_resources
	li   a2, 9
	call get_include
	beqz a0, .Lgc_no                # req asks resources but caller grant has none
	mv   a1, a0
	mv   a0, s1
	call resources_subset
	beqz a0, .Lgc_no
.Lgc_yes:
	li   a0, 1
	j    .Lgc_ret
.Lgc_no:
	li   a0, 0
.Lgc_ret:
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# grants_attenuated(a0 = requested grants array value, a1 = caller token data map) ->
# a0 = 1 if every requested grant is covered by some caller grant (i.e. the request does
# not widen scope beyond the caller's authority). Empty requested set → 1.
	.type grants_attenuated, @function
# s7=caller token data, s4=req cursor, s5=req count, s1=this requested grant map,
# s2=caller cursor, s3=caller count (saved/restored around the inner loop in place of the
# x86 push/pop %r14).
grants_attenuated:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s7, 56(sp)
	mv   s0, sp
	mv   s7, a1                     # caller token data
	call read_head                  # a0 = req grants → a0=first, a2=count
	mv   s4, a0                     # req cursor
	mv   s5, a2                     # req count
.Lga_req:
	beqz s5, .Lga_yes
	mv   s1, s4                     # this requested grant map
	# walk the caller grants, seeking one that covers this requested grant
	mv   a0, s7
	lla  a1, ka_grants
	li   a2, 6
	call map_find
	beqz a0, .Lga_no
	call read_head                  # caller grants → a0=first, a2=count
	mv   s2, a0                     # caller cursor
	mv   s3, a2                     # caller count (inner loop counter)
.Lga_caller:
	beqz s3, .Lga_uncovered
	mv   a0, s2
	mv   a1, s1
	call grant_covers
	bnez a0, .Lga_covered
	mv   a0, s2
	call skip_value
	mv   s2, a0
	addi s3, s3, -1
	j    .Lga_caller
.Lga_uncovered:
	j    .Lga_no
.Lga_covered:
	# advance req cursor past this grant
	mv   a0, s4
	call skip_value
	mv   s4, a0
	addi s5, s5, -1
	j    .Lga_req
.Lga_yes:
	li   a0, 1
	j    .Lga_ret
.Lga_no:
	li   a0, 0
.Lga_ret:
	ld   s7, 56(sp)
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# included_find_by_key(a0 = included map, a1 = key33 ptr) -> a0 = value entity ptr | 0.
# `included` is keyed by 33-byte content hashes; returns the value whose key bytes match.
	.type included_find_by_key, @function
# s4=key, s2=cursor, s1=remaining pairs, s5=key bytes.
included_find_by_key:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	mv   s0, sp
	mv   s4, a1                     # key
	call read_head                  # a0=included → a0=after, a1=5, a2=count
	mv   s2, a0                     # cursor
	mv   s1, a2                     # remaining pairs
.Lifk_l:
	beqz s1, .Lifk_no
	mv   a0, s2
	call read_head                  # key bstr: a0=bytes, a2=len
	mv   s5, a0                     # key bytes
	add  s2, a0, a2                 # cursor → value
	li   t0, 33
	bne  a2, t0, .Lifk_skipval
	mv   a0, s5
	mv   a1, s4
	li   a2, 33                     # memeq len (a2)
	call memeq
	bnez a0, .Lifk_found
.Lifk_skipval:
	mv   a0, s2
	call skip_value                 # skip value entity
	mv   s2, a0
	addi s1, s1, -1
	j    .Lifk_l
.Lifk_found:
	mv   a0, s2                     # value ptr (cursor sits at value)
	j    .Lifk_ret
.Lifk_no:
	li   a0, 0
.Lifk_ret:
	ld   s5, 40(sp)
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# find_req_sig(a0 = included map, a1 = author33, a2 = root_ch33) -> a0 = 64-byte
# signature ptr | 0. Scans `included` for a system/signature with signer==author and
# target==root_ch. (Pure reader — no FFI — so 16B alignment is irrelevant here.)
	.type find_req_sig, @function
# s4=author, s5=root_ch, s2=cursor, s1=remaining pairs, s7=value entity ptr,
# s8=sig data map.
find_req_sig:
	addi sp, sp, -80
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	sd   s7, 48(sp)
	sd   s8, 56(sp)
	mv   s0, sp
	mv   s4, a1                     # author
	mv   s5, a2                     # root_ch
	call read_head                  # a0=included → a0=after, a2=count
	mv   s2, a0                     # cursor
	mv   s1, a2                     # remaining pairs
.Lfrs_l:
	beqz s1, .Lfrs_no
	mv   a0, s2
	call read_head                  # key bstr: a0=bytes, a2=len
	add  s7, a0, a2                 # value entity ptr
	mv   a0, s7
	call skip_value                 # advance cursor to next pair NOW
	mv   s2, a0
	addi s1, s1, -1
	# value.type == "system/signature"?
	mv   a0, s7
	lla  a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Lfrs_l
	call get_text
	li   t0, 16
	bne  a2, t0, .Lfrs_l
	mv   a1, a0
	lla  a0, ta_sig
	li   a2, 16                     # memeq len (a2)
	call memeq
	beqz a0, .Lfrs_l
	# data map
	mv   a0, s7
	lla  a1, k_data
	li   a2, 4
	call map_find
	beqz a0, .Lfrs_l
	mv   s8, a0                     # sig data map
	# signer == author?
	mv   a0, s8
	lla  a1, ka_signer
	li   a2, 6
	call map_find
	beqz a0, .Lfrs_l
	call get_text
	li   t0, 33
	bne  a2, t0, .Lfrs_l
	mv   a1, a0
	mv   a0, s4                     # author
	li   a2, 33                     # memeq len (a2)
	call memeq
	beqz a0, .Lfrs_l
	# target == root_ch?
	mv   a0, s8
	lla  a1, ka_target
	li   a2, 6
	call map_find
	beqz a0, .Lfrs_l
	call get_text
	li   t0, 33
	bne  a2, t0, .Lfrs_l
	mv   a1, a0
	mv   a0, s5                     # root_ch
	li   a2, 33                     # memeq len (a2)
	call memeq
	beqz a0, .Lfrs_l
	# match → return signature bytes (64)
	mv   a0, s8
	lla  a1, ka_sig
	li   a2, 9
	call map_find
	beqz a0, .Lfrs_l
	call get_text                   # a0 = sig ptr, a2 = 64
	j    .Lfrs_ret
.Lfrs_no:
	li   a0, 0
.Lfrs_ret:
	ld   s8, 56(sp)
	ld   s7, 48(sp)
	ld   s5, 40(sp)
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 80
	ret

# mcmp33(a0=a, a1=b) -> a0 = a[i]-b[i] at first differing byte over 33 bytes (0 if equal).
# Sign gives bytewise order. Clobbers only a0, t0, t1, t2. Leaf. (a0/a1 stay the pointers;
# the a-byte lands in t0 so a0 — base + return — is not stomped mid-loop.)
	.type mcmp33, @function
mcmp33:
	li   t1, 0                      # i
.Lmc_l:
	li   t2, 33
	bgeu t1, t2, .Lmc_eq
	add  t2, a0, t1
	lbu  t0, 0(t2)
	add  t2, a1, t1
	lbu  t2, 0(t2)
	sub  t0, t0, t2
	bnez t0, .Lmc_diff
	addi t1, t1, 1
	j    .Lmc_l
.Lmc_diff:
	mv   a0, t0
	ret
.Lmc_eq:
	li   a0, 0
	ret

# find_sig_entity(a0=included map ptr) -> a0 = the system/signature entity ptr | 0
	.type find_sig_entity, @function
# s2=cursor, s1=count, s4=value entity ptr.
find_sig_entity:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	mv   s0, sp
	call read_head                  # a0=cursor, a2=count
	mv   s2, a0
	mv   s1, a2
.Lfse_loop:
	beqz s1, .Lfse_none
	mv   a0, s2
	call skip_value                 # skip key (33-byte hash)
	mv   s2, a0
	mv   s4, s2                     # value entity ptr
	mv   a0, s4
	lla  a1, k_type
	li   a2, 4
	call map_find
	beqz a0, .Lfse_skipval
	call get_text
	li   t0, 16
	bne  a2, t0, .Lfse_skipval
	mv   a1, a0
	lla  a0, ta_sig
	li   a2, 16                     # memeq len (a2)
	call memeq
	bnez a0, .Lfse_found
.Lfse_skipval:
	mv   a0, s4
	call skip_value
	mv   s2, a0
	addi s1, s1, -1
	j    .Lfse_loop
.Lfse_found:
	mv   a0, s4
	j    .Lfse_ret
.Lfse_none:
	li   a0, 0
.Lfse_ret:
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# build_echo_response(a0 = exec data map) — system/validate/echo: return the params
# entity verbatim as the result (the §6.11(b) request_id round-trip probe).
	.type build_echo_response, @function
# s2=params entity ptr, s4=params entity byte length, s6=writer cursor (was x86 r15),
# s5=env length. s6 is the GLOBAL cursor; here we set it up (mirrors x86 lea …,%r15).
build_echo_response:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s4, 32(sp)
	sd   s5, 40(sp)
	sd   s6, 48(sp)
	mv   s0, sp
	# params entity ptr + byte length
	lla  a1, ka_params
	li   a2, 6
	call map_find
	beqz a0, .Lecho_ret
	mv   s2, a0                     # params entity ptr
	call skip_value
	sub  a0, a0, s2
	mv   s4, a0                     # params entity byte length
	# resp data {result: <params entity raw>, status:200, request_id}
	lla  s6, b_ar_resp
	li   a1, 3
	call w_map
	lla  a0, k_result
	call w_cstr
	mv   a1, s2                     # params ptr
	mv   a2, s4                     # params len
	call w_raw                      # embed the params entity verbatim
	lla  a0, k_status
	call w_cstr
	li   a1, 200
	call w_uint
	lla  a0, k_rid
	call w_cstr
	lla  t0, g_rid_ptr
	ld   a1, 0(t0)
	lla  t0, g_rid_len
	ld   a2, 0(t0)
	call w_txt
	lla  a0, b_ar_resp
	sub  a2, s6, a0                 # resp data length
	lla  t0, g_ardlen
	sd   a2, 0(t0)
	lla  a0, t_resp
	li   a1, 32
	lla  a2, b_ar_resp
	lla  t0, g_ardlen
	ld   a3, 0(t0)
	lla  a4, resp_ch2
	call ec_content_hash
	# envelope {root: resp}
	lla  s6, b_ar_env
	li   a1, 1
	call w_map
	lla  a0, k_root
	call w_cstr
	lla  a0, t_resp
	lla  a1, b_ar_resp
	lla  t0, g_ardlen
	ld   a2, 0(t0)
	lla  a3, resp_ch2
	call w_entity
	lla  a0, b_ar_env
	sub  s5, s6, a0                # env length
	bswap32 t0, s5                 # big-endian 4-byte length prefix
	lla  t1, b_hdr
	sw   t0, 0(t1)
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_hdr
	li   a2, 4
	call write_all
	lla  t0, g_connfd
	ld   a0, 0(t0)
	lla  a1, b_ar_env
	mv   a2, s5                     # env length
	call write_all
.Lecho_ret:
	ld   s6, 48(sp)
	ld   s5, 40(sp)
	ld   s4, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

	.section .note.GNU-stack,"",@progbits
