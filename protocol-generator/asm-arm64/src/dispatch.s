// dispatch.s — frame read loop + envelope parse + routing + handlers.
// GAS aarch64. Entities/hashes via FFI; the envelope/data-map CBOR via cbor.s (A-ASM-004).
// Ported from asm-x86_64/src/dispatch.s. See macros.s for the x86-64→aarch64 convention
// (args x0-x5, ret x0, callee-saved x19-x28, CBOR writer cursor x24 global; read_head
// multi-returns x1=major/x2=arg; get_text returns x0=bytes/x2=len; memeq len in x2).

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
// F-peers (§5.4 is_peer_id): Base58 alphabet (Bitcoin), 58 bytes, no terminator needed —
// is_peer_id always scans exactly 58 entries. Ported from asm-x86_64/src/dispatch.s.
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

	.bss
	.lcomm b_req,    16777216
	.lcomm b_dhello, 4096
	.lcomm b_dresp,  8192
	.lcomm b_env,    16384
	.lcomm ch_hello, 64
	.lcomm ch_resp,  64
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
	// F-peers: extract_peer(execute.data.uri, local_peer_id) result — the target_peer used by
	// the §5.2 peers-scope check. Set by derive_handler; defaults to g_peerid/g_peerid_len.
	// .globl'd (like g_handler_ptr/len above) so tools/peers-scope-test.c can drive/inspect it.
	.globl g_target_peer_ptr
	.globl g_target_peer_len
	.lcomm g_target_peer_ptr, 8
	.lcomm g_target_peer_len, 8
	// ---- A-ASM-011 per-fork write store (path→entity) ----
	// store_idx: up to STORE_MAX entries × 32 B  [path_ptr, path_len, blob_ptr, blob_len].
	// store_arena: copy arena — the request buffer b_req is reused each frame, so a put must
	// COPY its path + entity bytes here to persist across frames of the connection. Sized for
	// a full --profile core sweep, which multiplexes every stateful probe (hundreds of puts,
	// incl. the concurrency sustained-load fan) onto ONE connection = ONE fork's store.
	.equ STORE_MAX,   8192
	.lcomm store_idx,   262144        // STORE_MAX × 32
	.lcomm store_count, 8
	.equ STORE_ARENA_CAP, 67108864    // 64 MiB
	.lcomm store_arena, 67108864
	.lcomm store_used,  8
	.lcomm b_prd_data,  256
	.lcomm prd_ch,      64
	.lcomm b_put_resp,  2048
	.lcomm put_resp_ch, 64
	.lcomm b_put_env,   4096
	.lcomm b_canon,     4096          // canonicalized store key: /{localPeerID}/{relative-path}
	// ---- listing scratch (trailing-slash get → system/tree/listing) ----
	// listing_ents: up to 384 distinct child segments × 32 B
	//   [0]=seg_ptr [8]=seg_len [16]=hash_ptr(0=null) [24]=has_children(0/1).
	.lcomm listing_ents, 12288
	.lcomm listing_n,   8
	.lcomm g_cpref_ptr, 8
	.lcomm g_cpref_len, 8
	.lcomm g_lprefix_ptr, 8
	.lcomm g_lprefix_len, 8
	.lcomm b_list_data, 2097152       // 2 MiB listing result data
	.lcomm list_data_ch, 64
	.lcomm b_list_env,  2097152
	// ---- system/handler register/unregister scratch ----
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
	// ---- multisig (§5.5) granter verification scratch ----
	.lcomm g_ms_thresh,  8
	.lcomm g_ms_valid,   8
	.lcomm g_ms_local,   8
	.lcomm g_ms_sigptr,  8
	.lcomm g_ms_sigs,    256          // up to 32 signer-hash pointers
	// ---- §5.5 delegation-chain walk + §5.5a canonicalization frames ----
	// A frame is a granter's peer_id (base58, <=128 bytes), derived from its system/peer
	// entity in `included` — it is not on the wire. `c` = the link nearer the leaf, `p` =
	// the link nearer the root; `s`/`q` are the sub/super sides of whichever comparison is
	// running, so the exclude direction can be reversed without copying a frame.
	.lcomm g_cfr,      128
	.lcomm g_cfrlen,   8
	.lcomm g_pfr,      128
	.lcomm g_pfrlen,   8
	.lcomm g_sfr_ptr,  8
	.lcomm g_sfr_len,  8
	.lcomm g_qfr_ptr,  8
	.lcomm g_qfr_len,  8
	.lcomm g_dfr,      128            // dispatch-surface frame (the presented cap's granter)
	.lcomm g_dfrlen,   8
	.lcomm b_canon_a,  1024           // canonicalized child / request-target
	.lcomm b_canon_b,  1024           // canonicalized parent / grant pattern
	.lcomm g_pgee,     48             // child link's granter hash, carried across one hop
	.lcomm g_now,      8              // §5.5 `t` — sampled ONCE per verdict, never per link
	.lcomm g_link_ch,  64             // recomputed content hash of the link under test
	// ---- §6.2 CAP-5 / §5.6 MIN_DEFINED mint ceiling ----
	.lcomm g_caller_td,  8            // the caller capability's token data (the bounding term)
	.lcomm g_params_data, 8           // request params.data (carries ttl_ms)
	.lcomm g_exp_have,   8
	.lcomm g_expv,       8
	// ---- revoke scratch ----
	.lcomm b_revoke_data, 512
	.lcomm revoke_ch,    64
	.lcomm b_revoke_ent, 1024


	.text
	.globl peer_bootstrap
	.type peer_bootstrap, %function
// Compute this peer's identity_hash = content_hash of its system/peer entity, and
// cache the peer-entity data bytes (reused when this peer is emitted in `included`).
peer_bootstrap:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x24, [sp, #16]              // preserve the global cursor across this build
	adr_l x24, b_peerdata           // x24 = writer cursor
	mov  x1, #2
	bl   w_map
	adr_l x0, ka_ktype
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_pubkey
	bl   w_cstr
	adr_l x1, g_pubkey
	mov  x2, #32
	bl   w_bstr
	adr_l x9, b_peerdata
	sub  x2, x24, x9                 // peerdata_len = cursor - b_peerdata
	adr_l x9, g_peerdata_len
	str  x2, [x9]
	adr_l x0, ta_peer
	mov  x1, #11
	adr_l x2, b_peerdata
	adr_l x9, g_peerdata_len
	ldr  x3, [x9]
	adr_l x4, g_identity_hash
	bl   ec_content_hash
	ldr  x24, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// =====================================================================
// conn_serve(x0 = connfd) — read framed requests, dispatch each, until EOF.
// =====================================================================
	.globl conn_serve
	.type conn_serve, %function
// x19 = connfd (callee-saved), x20 = frame/remaining length across drain.
conn_serve:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	mov  x19, x0                     // connfd
	adr_l x9, g_connfd
	str  x19, [x9]
	bl   seed_dispatch_entities      // publish §6.2 native dispatch entities into this fork
.Lcs_loop:
	// read 4-byte BE length header
	mov  x0, x19
	adr_l x1, b_hdr
	mov  x2, #4
	bl   read_full
	cmp  x0, #4
	b.ne .Lcs_done
	adr_l x9, b_hdr
	ldr  w9, [x9]
	rev  w9, w9                      // BE → host
	cbz  w9, .Lcs_loop               // zero-length frame: ignore
	movz w10, #0x100, lsl #16        // 0x1000000: > 16 MiB (§9.1 default payload cap) → 413, keep serving
	cmp  w9, w10
	b.hi .Lcs_oversize
	// read body
	mov  x0, x19
	adr_l x1, b_req
	mov  w2, w9                      // frame len (zero-extended)
	mov  x20, x2
	bl   read_full
	cmp  x0, x20
	b.ne .Lcs_done
	bl   dispatch
	b    .Lcs_loop
.Lcs_oversize:
	// §4.10(a): answer 413 payload_too_large NOW, then close. request_id is unknown
	// (the body was never parsed) → echo empty, which the section's emission shape
	// explicitly provides for: "SHOULD emit a 413 correlated by request_id when the
	// id is available, and otherwise MAY close the connection after a best-effort
	// coded frame".
	//
	// This used to DRAIN the whole declared body first — in <=1 MiB chunks, up to the
	// 4 GiB a 32-bit length header can name — so the connection could stay framed and
	// keep serving. That reads as the more conformant choice and is the opposite:
	// §4.10(a) requires rejecting "BEFORE fully buffering or decoding it where the
	// transport allows", and the drain is the fully-buffering it forbids, done one
	// buffer at a time. A sender that declares 4 GiB and sends 1 KiB parks the child
	// in read(2) for as long as it likes, and no 413 is ever emitted because the peer
	// is still politely waiting for the payload it already knows it will refuse.
	// Measured on x86-64 2026-08-29: the oracle timed out reading the response every
	// time and recorded "connection terminated without a 413 frame".
	//
	// Staying framed is worth nothing once the frame is known to be unservable, and
	// the connection is the attacker's to waste, not ours.
	adr_l x9, g_rid_len
	str  xzr, [x9]
	mov  x0, #413
	adr_l x1, ec_payload_too_large
	bl   send_error
	b    .Lcs_done
.Lcs_done:
	mov  x0, x19
	ksys SYS_close
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// read_full(x0=fd, x1=buf, x2=n) -> x0 = bytes read (n on success)
	.type read_full, %function
// x19=fd, x20=buf, x21=remaining, x22=got.
read_full:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x19, x0                     // fd
	mov  x20, x1                     // buf
	mov  x21, x2                     // remaining
	mov  x22, #0                     // got
.Lrf:
	cbz  x21, .Lrf_done
	mov  x0, x19
	add  x1, x20, x22
	mov  x2, x21
	ksys SYS_read
	cmp  x0, #0
	b.le .Lrf_done                   // EOF/error
	add  x22, x22, x0
	sub  x21, x21, x0
	b    .Lrf
.Lrf_done:
	mov  x0, x22
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// =====================================================================
// dispatch — parse b_req envelope, route by operation. (only hello for now)
// =====================================================================
	.type dispatch, %function
// x19 = exec data map (rbx). op ptr/len (x86 held them in volatile r8/r9 across memeq,
// which preserves r8/r9; aarch64 memeq clobbers x9/x10, so promote to callee-saved
// x20 = op ptr, x21 = op len).
dispatch:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	// root = map_find(b_req, "root")
	adr_l x0, b_req
	adr_l x1, k_root
	mov  x2, #4
	bl   map_find
	cbz  x0, .Ld_ret
	adr_l x9, g_root_ptr
	str  x0, [x9]
	// §7a: a root of type system/protocol/execute/response is a reply to one of our outbound
	// reentry echoes — demux it to its pending dispatch-outbound instead of dispatching.
	// x0 already = root ptr
	adr_l x1, k_type
	mov  x2, #4
	bl   map_find
	cbz  x0, .Ld_notresp
	bl   get_text
	cmp  x2, #32
	b.ne .Ld_notresp
	mov  x1, x0
	adr_l x0, t_resp
	mov  x2, #32                     // memeq len in x2
	bl   memeq
	cbz  x0, .Ld_notresp
	adr_l x9, g_root_ptr
	ldr  x0, [x9]
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Ld_ret
	bl   handle_dispatch_response
	b    .Ld_ret
.Ld_notresp:
	// exec = map_find(root, "data")
	adr_l x9, g_root_ptr
	ldr  x0, [x9]
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Ld_ret
	mov  x19, x0                     // x19 = exec data map
	// request_id → save
	mov  x0, x19
	adr_l x1, k_rid
	mov  x2, #10
	bl   map_find
	cbz  x0, .Ld_ret
	bl   get_text                    // x0=ptr, x2=len
	adr_l x9, g_rid_ptr
	str  x0, [x9]
	adr_l x9, g_rid_len
	str  x2, [x9]
	// operation
	mov  x0, x19
	adr_l x1, k_op
	mov  x2, #9
	bl   map_find
	cbz  x0, .Ld_ret
	bl   get_text                    // x0=opptr, x2=oplen
	// route: save op (ptr in x0, len in x2) then compare
	mov  x20, x0                     // op ptr
	mov  x21, x2                     // op len
	// Every branch below dispatches on LENGTH first and only then compares bytes, so a
	// length collision with an op we do route is the case to get right: a byte mismatch
	// must fall through to .Ld_unknown (→ 501 unsupported_operation), never to .Ld_ret.
	// Falling to .Ld_ret answers NOTHING, and §4.9(c) deliver-or-signal makes that the
	// one outcome a peer may not produce — the caller cannot tell it from a dead peer and
	// waits out its own timeout. Measured 2026-08-30 on asm-x86_64: `ping` collides with
	// `echo` at length 4 and was dropped on exactly this branch. It costs the caller a
	// full 20 s read deadline EVERY connection, which is why t2_2_connection_churn
	// consumed the entire 10-minute budget across 29 of its 100 cycles and starved nine
	// categories — a §4.9(c) violation presenting as a connection-pressure failure.
	// op == "hello"?
	cmp  x21, #5
	b.ne .Ld_try_auth
	mov  x1, x20
	adr_l x0, v_hello
	mov  x2, #5
	bl   memeq
	cbz  x0, .Ld_unknown             // len 5 but not "hello" → 501, never a silent drop
	// §4.5 negotiation: reject a hello whose advertised hash_formats/key_types are
	// disjoint from ours (400) before building the happy-path response.
	mov  x0, x19                     // exec data map
	bl   check_hello_negotiation
	cbnz x0, .Ld_ret                 // rejected (400 already sent)
	bl   build_hello_response
	b    .Ld_ret
.Ld_try_auth:
	// op == "authenticate"?
	cmp  x21, #12
	b.ne .Ld_try_echo
	mov  x1, x20
	adr_l x0, va_authenticate
	mov  x2, #12
	bl   memeq
	cbz  x0, .Ld_unknown             // len 12 but not "authenticate" → 501
	mov  x0, x19                     // exec data map ptr
	bl   build_authenticate_response
	b    .Ld_ret
.Ld_try_echo:
	// op == "echo"? (system/validate/echo)
	cmp  x21, #4
	b.ne .Ld_try_get
	mov  x1, x20
	adr_l x0, va_echo
	mov  x2, #4
	bl   memeq
	cbz  x0, .Ld_unknown             // len 4 but not "echo" — e.g. "ping" — → 501
	mov  x0, x19
	bl   build_echo_response
	b    .Ld_ret
.Ld_try_get:
	// op == "get"? (system/tree get) — resolve against the store + embedded read-only store.
	cmp  x21, #3
	b.ne .Ld_try_request
	mov  x1, x20
	adr_l x0, va_get
	mov  x2, #3
	bl   memeq
	cbz  x0, .Ld_try_put             // len 3 but not "get" → maybe "put"
	mov  x0, x19                     // exec data map ptr
	bl   serve_tree_get
	b    .Ld_ret
.Ld_try_put:
	// op == "put"? (system/tree put) — write into the per-fork store (A-ASM-011).
	cmp  x21, #3
	b.ne .Ld_try_request
	mov  x1, x20
	adr_l x0, va_put
	mov  x2, #3
	bl   memeq
	cbz  x0, .Ld_try_request
	mov  x0, x19                     // exec data map ptr
	bl   serve_tree_put
	b    .Ld_ret
.Ld_try_request:
	// op == "request"? (system/capability request) — mint a token per params.data.grants.
	cmp  x21, #7
	b.ne .Ld_try_register
	mov  x1, x20
	adr_l x0, va_request
	mov  x2, #7
	bl   memeq
	cbz  x0, .Ld_try_register
	mov  x0, x19                     // exec data map ptr
	bl   build_request_response
	b    .Ld_ret
.Ld_try_register:
	// op == "register"? (system/handler register) — write handler entities to the store.
	cmp  x21, #8
	b.ne .Ld_try_unregister
	mov  x1, x20
	adr_l x0, va_register
	mov  x2, #8
	bl   memeq
	cbz  x0, .Ld_try_delegate
	mov  x0, x19
	bl   serve_register
	b    .Ld_ret
.Ld_try_delegate:
	// op == "delegate"? (system/capability delegate) — same-peer-only; unsupported in v1.
	mov  x1, x20
	adr_l x0, va_delegate
	mov  x2, #8
	bl   memeq
	cbz  x0, .Ld_try_dispatch
	mov  x0, x19
	bl   serve_delegate
	b    .Ld_ret
.Ld_try_dispatch:
	// op == "dispatch"? (§7a system/validate/dispatch-outbound) — originate a reentry echo.
	mov  x1, x20
	adr_l x0, va_dispatch
	mov  x2, #8
	bl   memeq
	cbz  x0, .Ld_unknown
	mov  x0, x19
	bl   serve_dispatch_outbound
	b    .Ld_ret
.Ld_try_unregister:
	// op == "unregister"? (system/handler unregister) — remove handler entities.
	cmp  x21, #10
	b.ne .Ld_try_configure
	mov  x1, x20
	adr_l x0, va_unregister
	mov  x2, #10
	bl   memeq
	cbz  x0, .Ld_unknown
	mov  x0, x19
	bl   serve_unregister
	b    .Ld_ret
.Ld_try_configure:
	// op == "configure"? (system/capability configure) — write a peer policy-entry.
	cmp  x21, #9
	b.ne .Ld_try_revoke
	mov  x1, x20
	adr_l x0, va_configure
	mov  x2, #9
	bl   memeq
	cbz  x0, .Ld_unknown
	mov  x0, x19
	bl   serve_configure
	b    .Ld_ret
.Ld_try_revoke:
	// op == "revoke"? (system/capability revoke) — write a revocation marker.
	cmp  x21, #6
	b.ne .Ld_unknown
	mov  x1, x20
	adr_l x0, va_revoke
	mov  x2, #6
	bl   memeq
	cbz  x0, .Ld_unknown
	mov  x0, x19
	bl   serve_revoke
	b    .Ld_ret
.Ld_unknown:
	// An operation this peer doesn't route falls into two classes:
	//  - a KNOWN vocabulary op (delegate/configure/revoke/register/unregister/put) we don't
	//    (yet) implement gets an authorization decision — if the presented capability doesn't
	//    cover it, that's a 403 denial (verify_get_scope); otherwise it falls through to 501.
	//  - a genuinely UNKNOWN op → 501 unsupported_operation up front.
	// (A silent no-reply would block validate-peer ~20s/probe, so we always answer.)
	mov  x0, x20                     // op ptr
	mov  x1, x21                     // op len
	bl   op_is_known
	cbz  x0, .Ld_501                 // unknown op → 501
	mov  x0, x19                     // exec data map
	bl   verify_get_scope
	cbnz x0, .Ld_ret                 // 403 already sent
.Ld_501:
	mov  x0, #501
	adr_l x1, ec_unsupported_op
	bl   send_error
.Ld_ret:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// op_is_known(x0 = op ptr, x1 = op len) -> x0 = 1 if op is a known capability/handler/tree
// write op we recognise but don't route to a dedicated handler (delegate/configure/revoke/
// register/unregister/put). Such ops get an authorization decision (403); anything else is
// a genuinely unknown operation (501 unsupported_operation).
	.type op_is_known, %function
// x19 = op ptr, x20 = op len (survive memeq).
op_is_known:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	mov  x19, x0                     // op ptr
	mov  x20, x1                     // op len
	cmp  x20, #8
	b.ne .Loik_c9
	mov  x0, x19
	adr_l x1, va_delegate
	mov  x2, #8
	bl   memeq
	cbnz x0, .Loik_yes
	mov  x0, x19
	adr_l x1, va_register
	mov  x2, #8
	bl   memeq
	cbnz x0, .Loik_yes
	b    .Loik_no
.Loik_c9:
	cmp  x20, #9
	b.ne .Loik_c6
	mov  x0, x19
	adr_l x1, va_configure
	mov  x2, #9
	bl   memeq
	cbnz x0, .Loik_yes
	b    .Loik_no
.Loik_c6:
	cmp  x20, #6
	b.ne .Loik_c10
	mov  x0, x19
	adr_l x1, va_revoke
	mov  x2, #6
	bl   memeq
	cbnz x0, .Loik_yes
	b    .Loik_no
.Loik_c10:
	cmp  x20, #10
	b.ne .Loik_c3
	mov  x0, x19
	adr_l x1, va_unregister
	mov  x2, #10
	bl   memeq
	cbnz x0, .Loik_yes
	b    .Loik_no
.Loik_c3:
	cmp  x20, #3
	b.ne .Loik_no
	mov  x0, x19
	adr_l x1, va_put
	mov  x2, #3
	bl   memeq
	cbnz x0, .Loik_yes
.Loik_no:
	mov  x0, #0
	b    .Loik_ret
.Loik_yes:
	mov  x0, #1
.Loik_ret:
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// =====================================================================
// build_hello_response — construct + send a valid hello EXECUTE_RESPONSE.
// =====================================================================
	.type build_hello_response, %function
// x24 = writer cursor (global). x19 = env len across the two write_all calls.
build_hello_response:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x24, [sp, #16]
	// nonce (32 CSPRNG bytes)
	adr_l x0, b_nonce
	mov  x1, #32
	mov  x2, #0
	ksys SYS_getrandom
	// timestamp ms = sec*1000 + nsec/1e6
	mov  x0, #0                      // CLOCK_REALTIME
	adr_l x1, b_ts
	ksys SYS_clock_gettime
	adr_l x9, b_ts
	ldr  x10, [x9]                   // sec
	mov  x11, #1000
	mul  x10, x10, x11               // sec*1000
	adr_l x9, b_ts
	ldr  x12, [x9, #8]              // nsec
	movz x13, #0x4240               // 1000000 = 0x0F4240
	movk x13, #0x000F, lsl #16
	udiv x12, x12, x13               // nsec/1e6
	add  x10, x10, x12
	adr_l x9, g_ms
	str  x10, [x9]

	// ---- D_hello (a6) into b_dhello ----
	adr_l x24, b_dhello
	mov  x1, #6
	bl   w_map
	adr_l x0, k_nonce
	bl   w_cstr
	adr_l x1, b_nonce
	mov  x2, #32
	bl   w_bstr
	adr_l x0, k_peerid
	bl   w_cstr
	adr_l x1, g_peerid
	adr_l x9, g_peerid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x0, k_ktypes
	bl   w_cstr
	mov  x1, #2
	bl   w_arr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, v_ed448
	bl   w_cstr
	adr_l x0, k_protos
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, v_ecore
	bl   w_cstr
	adr_l x0, k_ts
	bl   w_cstr
	adr_l x9, g_ms
	ldr  x1, [x9]
	bl   w_uint
	adr_l x0, k_hfmts
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, v_ecfv1
	bl   w_cstr
	// dhello_len = x24 - b_dhello
	adr_l x9, b_dhello
	sub  x2, x24, x9
	adr_l x9, g_dhlen
	str  x2, [x9]
	// ch_hello = ec_content_hash("system/protocol/connect/hello"(29), D_hello)
	adr_l x0, t_hello
	mov  x1, #29
	adr_l x2, b_dhello
	adr_l x9, g_dhlen
	ldr  x3, [x9]
	adr_l x4, ch_hello
	bl   ec_content_hash

	// ---- D_resp (a3) into b_dresp ----
	adr_l x24, b_dresp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result               // "result" → hello entity
	bl   w_cstr
	mov  x1, #3
	bl   w_map
	adr_l x0, k_data
	bl   w_cstr
	adr_l x1, b_dhello               // embed D_hello verbatim
	adr_l x9, g_dhlen
	ldr  x2, [x9]
	bl   w_raw
	adr_l x0, k_type
	bl   w_cstr
	adr_l x0, t_hello
	bl   w_cstr
	adr_l x0, k_chash
	bl   w_cstr
	adr_l x1, ch_hello
	mov  x2, #33
	bl   w_bstr
	adr_l x0, k_status               // "status" → 200
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid                  // "request_id" → echo
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	// dresp_len
	adr_l x9, b_dresp
	sub  x2, x24, x9
	adr_l x9, g_drlen
	str  x2, [x9]
	// ch_resp = ec_content_hash("system/protocol/execute/response"(32), D_resp)
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_dresp
	adr_l x9, g_drlen
	ldr  x3, [x9]
	adr_l x4, ch_resp
	bl   ec_content_hash

	// ---- envelope (a1) into b_env ----
	adr_l x24, b_env
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	mov  x1, #3
	bl   w_map
	adr_l x0, k_data
	bl   w_cstr
	adr_l x1, b_dresp                // embed D_resp verbatim
	adr_l x9, g_drlen
	ldr  x2, [x9]
	bl   w_raw
	adr_l x0, k_type
	bl   w_cstr
	adr_l x0, t_resp
	bl   w_cstr
	adr_l x0, k_chash
	bl   w_cstr
	adr_l x1, ch_resp
	mov  x2, #33
	bl   w_bstr
	// env_len
	adr_l x9, b_env
	sub  x19, x24, x9                // x19 = env len
	// frame header: 4-byte BE len
	rev  w9, w19
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_env
	mov  x2, x19
	bl   write_all
	ldp  x19, x24, [sp, #16]
	ldp  x29, x30, [sp], #48
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
ka_parent:   .asciz "parent"
ka_threshold: .asciz "threshold"
ka_signers:  .asciz "signers"
// ---- §5.5 delegation-chain / §5.6 attenuation vocabulary ----
ka_exclude:  .asciz "exclude"
ka_constraints: .asciz "constraints"
ka_allowances: .asciz "allowances"
ka_deleg_caveats: .asciz "delegation_caveats"
ka_no_delegation: .asciz "no_delegation"
ka_max_deleg_depth: .asciz "max_delegation_depth"
ka_max_deleg_ttl: .asciz "max_delegation_ttl"
ka_ttl_ms:   .asciz "ttl_ms"

	.bss
	// Sized for the full 16 MiB entity cap: a get now serves store-written entities of
	// arbitrary size (the concurrency `slow` binding is deliberately large), whose bytes are
	// copied verbatim into the response — a 2 KiB buffer overflowed into neighbouring .bss.
	.lcomm b_get_data,   17825792     // 17 MiB (16 MiB entity + envelope headroom)
	.lcomm get_data_ch,  64
	.lcomm b_get_env,    17825792
	.lcomm b_incl_tab,   512
	.lcomm tok_recompute_ch, 64
	.lcomm b_derived_pid, 128
	.lcomm g_derived_pid_len, 8
	.lcomm g_auth_hash,  64
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
	// RT-6 (§4.6): set once authenticate succeeds on this connection; a second authenticate
	// frame on the same connection must be rejected (401 invalid_nonce), not re-processed.
	.lcomm g_established, 8
	// ---- §7a dispatch-outbound reentry (bidirectional dispatch + demux) ----
	// pending_tab: 16 entries × 80 B  [0]=echo_rid(32) [32]=erid_len [40]=disp_rid(32) [72]=drid_len
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
// w_entity(x0=type_cstr, x1=data_ptr, x2=data_len, x3=chash_ptr) — emit an
// entity map {data:<raw>, type:<cstr>, content_hash:<33>}. Uses x24 cursor.
	.type w_entity, %function
w_entity:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x19, x0                     // type cstr
	mov  x20, x1                     // data ptr
	mov  x21, x2                     // data len
	mov  x22, x3                     // chash ptr
	mov  x1, #3
	bl   w_map
	adr_l x0, k_data
	bl   w_cstr
	mov  x1, x20                     // data ptr
	mov  x2, x21                     // data len
	bl   w_raw
	adr_l x0, k_type
	bl   w_cstr
	mov  x0, x19                     // type cstr
	bl   w_cstr
	adr_l x0, k_chash
	bl   w_cstr
	mov  x1, x22                     // chash ptr
	mov  x2, #33
	bl   w_bstr
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// now_ms() -> x0 = wall-clock ms
	.type now_ms, %function
now_ms:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	mov  x0, #0                      // CLOCK_REALTIME
	adr_l x1, b_ts
	ksys SYS_clock_gettime
	adr_l x9, b_ts
	ldr  x10, [x9]                   // tv_sec
	mov  x11, #1000
	mul  x10, x10, x11               // sec * 1000
	ldr  x12, [x9, #8]              // tv_nsec
	mov  x13, #16960                 // 1000000 = 0xF4240
	movk x13, #0xF, lsl #16
	udiv x12, x12, x13               // nsec / 1000000
	add  x0, x10, x12
	ldp  x29, x30, [sp], #16
	ret

// emit_grants — emit the grants ARRAY (cursor x24) per g_opengrants.
	.type emit_grants, %function
emit_grants:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	adr_l x9, g_opengrants
	ldr  x9, [x9]
	cbz  x9, .Leg_floor
	mov  x1, #1
	bl   w_arr
	ldp  x29, x30, [sp], #16
	b    emit_grant_wild
.Leg_floor:
	mov  x1, #2
	bl   w_arr
	bl   emit_grant_floor1
	ldp  x29, x30, [sp], #16
	b    emit_grant_floor2

// {peers:[*], handlers:[*], resources:[*,/*/*], operations:[*]}
	.type emit_grant_wild, %function
emit_grant_wild:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_peers
	bl   w_incl1
	adr_l x0, ka_handlers
	bl   w_incl1
	adr_l x0, ka_resources
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #2
	bl   w_arr
	adr_l x0, va_star
	bl   w_cstr
	adr_l x0, va_star2
	bl   w_cstr
	adr_l x0, ka_operations
	bl   w_incl1
	ldp  x29, x30, [sp], #16
	ret

// w_incl1(x0=field_cstr) — emit  <field>: {include:["*"]}
	.type w_incl1, %function
w_incl1:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, va_star
	bl   w_cstr
	ldp  x29, x30, [sp], #16
	ret

// floor grant 1: {handlers:{include:[system/tree]}, resources:{include:[system/type/*,
//   system/handler/*]}, operations:{include:[get]}}
	.type emit_grant_floor1, %function
emit_grant_floor1:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	mov  x1, #3
	bl   w_map
	adr_l x0, ka_handlers
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, va_systree
	bl   w_cstr
	adr_l x0, ka_resources
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #2
	bl   w_arr
	adr_l x0, va_systype_g
	bl   w_cstr
	adr_l x0, va_syshandler_g
	bl   w_cstr
	adr_l x0, ka_operations
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, va_get
	bl   w_cstr
	ldp  x29, x30, [sp], #16
	ret

// floor grant 2: {handlers:{include:[system/capability]}, resources:{include:[]},
//   operations:{include:[request]}}
	.type emit_grant_floor2, %function
emit_grant_floor2:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	mov  x1, #3
	bl   w_map
	adr_l x0, ka_handlers
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, va_syscap
	bl   w_cstr
	adr_l x0, ka_resources
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #0
	bl   w_arr
	adr_l x0, ka_operations
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_include
	bl   w_cstr
	mov  x1, #1
	bl   w_arr
	adr_l x0, va_request
	bl   w_cstr
	ldp  x29, x30, [sp], #16
	ret
// build_authenticate_response(x0 = exec data map ptr)
	.type build_authenticate_response, %function
// Callee-saved held across the build:
//   x21 = exec data map (was r12), x22 = params entity / later sig data map (was r13),
//   x23 = pdata (was r14), x24 = CBOR cursor (was r15, global), x19 = sig ptr temp (was rbx).
build_authenticate_response:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]
	mov  x21, x0                     // exec data map
	// RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established connection must
	// not be re-processed (it would re-verify the same still-cached nonce and re-issue a grant).
	// The nonce is documented single-use — reject outright, before any parsing/verification.
	adr_l x9, g_established
	ldr  x9, [x9]
	cbz  x9, .Lauth_not_replay
	mov  x0, #401
	adr_l x1, ec_invalid_nonce
	bl   send_error
	b    .Lauth_ret
.Lauth_not_replay:
	// params entity
	mov  x0, x21
	adr_l x1, ka_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lauth_ret
	mov  x22, x0                     // params entity
	// params data map
	mov  x0, x22
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	mov  x23, x0                     // params data (pdata)
	// §7.1 agility: reject an unsupported key_type at the handshake (400 unsupported_key_type)
	// before the identity checks. key_type must be the text "ed25519" (the core floor); any
	// other value — including the numeric 0xFD experimental code — is unsupported.
	mov  x0, x23
	adr_l x1, ka_ktype
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lauth_kt_ok            // absent → lenient (identity checks still run)
	bl   read_head                   // x0 = text ptr, x1 = major, x2 = len
	cmp  x1, #3                      // must be a text string
	b.ne .Lauth_bad_kt
	cmp  x2, #7
	b.ne .Lauth_bad_kt
	adr_l x1, v_ed25519
	mov  x2, #7
	bl   memeq
	cbz  x0, .Lauth_bad_kt
.Lauth_kt_ok:
	// client public_key → g_client_pubkey (32)
	mov  x0, x23
	adr_l x1, ka_pubkey
	mov  x2, #10
	bl   map_find
	bl   get_text                    // x0=ptr, x2=len(32)
	mov  x1, x0                      // src
	adr_l x0, g_client_pubkey        // dst
	mov  x2, #32
	bl   mcpy
	// grantee = ec_content_hash("system/peer", client_peer{key_type,public_key})
	adr_l x24, b_clientpeer
	mov  x1, #2
	bl   w_map
	adr_l x0, ka_ktype
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_pubkey
	bl   w_cstr
	adr_l x1, g_client_pubkey
	mov  x2, #32
	bl   w_bstr
	// ec_content_hash(type, type_len, data, data_len, out) → x0..x4
	// (x86: rdi=type, rsi=type_len, rdx=data, rcx=data_len, r8=out)
	adr_l x0, ta_peer
	mov  x1, #11
	adr_l x2, b_clientpeer
	adr_l x9, b_clientpeer
	sub  x3, x24, x9                 // client peer data len
	adr_l x4, g_grantee
	bl   ec_content_hash

	// ================= §5.2 verification (reject → 401) =================
	// 1. nonce echo — params.nonce must equal the nonce we issued (b_nonce)
	mov  x0, x23                     // pdata
	adr_l x1, k_nonce
	mov  x2, #5
	bl   map_find
	cbz  x0, .Lauth_bad_nonce
	bl   get_text
	cmp  x2, #32
	b.ne .Lauth_bad_nonce
	adr_l x1, b_nonce
	mov  x2, #32
	bl   memeq
	cbz  x0, .Lauth_bad_nonce
	// 2. peer_id binding — base58(client pubkey) must equal params.peer_id
	// ec_peerid_format(key_type, hash_type, digest, digest_len, out, out_cap, out_len) → x0..x6
	mov  x0, #1
	mov  x1, #0
	adr_l x2, g_client_pubkey
	mov  x3, #32
	adr_l x4, b_derived_pid
	mov  x5, #128
	adr_l x6, g_derived_pid_len
	bl   ec_peerid_format
	mov  x0, x23
	adr_l x1, k_peerid
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lauth_bad_pid
	bl   get_text                    // x0=ptr, x2=len
	adr_l x9, g_derived_pid_len
	ldr  x9, [x9]
	cmp  x2, x9
	b.ne .Lauth_bad_pid
	adr_l x1, b_derived_pid
	// x2 already = len (the compare length)
	bl   memeq
	cbz  x0, .Lauth_bad_pid
	// 3. PoP signature — verify client sig over the authenticate entity content_hash
	mov  x0, x23
	bl   skip_value
	sub  x9, x0, x23                 // pdata len
	// ec_content_hash(type, type_len, data, data_len, out) → x0..x4
	adr_l x0, ta_auth
	mov  x1, #36
	mov  x2, x23                     // data = pdata
	mov  x3, x9                      // data_len
	adr_l x4, g_auth_hash
	bl   ec_content_hash
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lauth_bad_sig
	bl   find_sig_entity
	cbz  x0, .Lauth_bad_sig
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	mov  x22, x0                     // sig data map
	mov  x0, x22
	adr_l x1, ka_sig
	mov  x2, #9
	bl   map_find
	bl   get_text                    // x0 = sig(64)
	mov  x19, x0
	// ec_ed25519_verify(pubkey, msg, msg_len, sig) → x0..x3
	adr_l x0, g_client_pubkey
	adr_l x1, g_auth_hash
	mov  x2, #33
	mov  x3, x19
	bl   ec_ed25519_verify
	cbnz w0, .Lauth_bad_sig
	// 4. impersonation — signature.signer must equal client identity_hash (grantee)
	mov  x0, x22
	adr_l x1, ka_signer
	mov  x2, #6
	bl   map_find
	bl   get_text
	adr_l x1, g_grantee
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lauth_bad_imp
	// ================= verification passed =================

	// RT-6 (§4.6): mark this connection established so a replayed authenticate is rejected.
	adr_l x9, g_established
	mov  x10, #1
	str  x10, [x9]

	bl   now_ms
	adr_l x9, g_created
	str  x0, [x9]

	// ---- token data ----
	adr_l x24, b_tokdata
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_grants
	bl   w_cstr
	bl   emit_grants
	adr_l x0, ka_grantee
	bl   w_cstr
	adr_l x1, g_grantee
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_granter
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_created
	bl   w_cstr
	adr_l x9, g_created
	ldr  x1, [x9]
	bl   w_uint
	adr_l x9, b_tokdata
	sub  x2, x24, x9
	adr_l x9, g_toklen
	str  x2, [x9]                    // token data len
	// tok_ch = ec_content_hash("system/capability/token", token_data)
	adr_l x0, ta_token
	mov  x1, #23
	adr_l x2, b_tokdata
	adr_l x9, g_toklen
	ldr  x3, [x9]
	adr_l x4, tok_ch
	bl   ec_content_hash
	// tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	adr_l x0, g_seed
	adr_l x1, tok_ch
	mov  x2, #33
	adr_l x3, tok_sig
	bl   ec_ed25519_sign

	// ---- signature entity data {signer,target,algorithm,signature} ----
	adr_l x24, b_sigdata
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_signer
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_target
	bl   w_cstr
	adr_l x1, tok_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_algo
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_sig
	bl   w_cstr
	adr_l x1, tok_sig
	mov  x2, #64
	bl   w_bstr
	adr_l x9, b_sigdata
	sub  x2, x24, x9
	adr_l x9, g_sigdlen
	str  x2, [x9]
	adr_l x0, ta_sig
	mov  x1, #16
	adr_l x2, b_sigdata
	adr_l x9, g_sigdlen
	ldr  x3, [x9]
	adr_l x4, sig_ch
	bl   ec_content_hash

	// ---- grant result data {token: tok_ch} ----
	adr_l x24, b_grantdata
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_token
	bl   w_cstr
	adr_l x1, tok_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x9, b_grantdata
	sub  x2, x24, x9
	adr_l x9, g_grlen
	str  x2, [x9]
	adr_l x0, ta_grant
	mov  x1, #23
	adr_l x2, b_grantdata
	adr_l x9, g_grlen
	ldr  x3, [x9]
	adr_l x4, grant_ch
	bl   ec_content_hash

	// ---- response data {result, status, request_id} ----
	adr_l x24, b_ar_resp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	// w_entity(type_cstr, data_ptr, data_len, chash_ptr) → x0..x3
	adr_l x0, ta_grant               // result entity = the grant
	adr_l x1, b_grantdata
	adr_l x9, g_grlen
	ldr  x2, [x9]
	adr_l x3, grant_ch
	bl   w_entity
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_ar_resp
	sub  x2, x24, x9
	adr_l x9, g_ardlen
	str  x2, [x9]
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x3, [x9]
	adr_l x4, resp_ch2
	bl   ec_content_hash

	// ---- envelope {root, included} ----
	adr_l x24, b_ar_env
	mov  x1, #2
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x2, [x9]
	adr_l x3, resp_ch2
	bl   w_entity
	adr_l x0, ka_included
	bl   w_cstr
	// Populate the included-entry table {key_ptr,type_ptr,data_ptr,data_len,ch_ptr}
	// then emit sorted by 33-byte key — ECF §4.2 canonical map ordering (the three
	// keys are content hashes, so the order is runtime-dependent). 40 bytes/entry.
	adr_l x3, b_incl_tab
	// entry 0: token
	adr_l x9, tok_ch
	str  x9, [x3, #0]
	adr_l x9, ta_token
	str  x9, [x3, #8]
	adr_l x9, b_tokdata
	str  x9, [x3, #16]
	adr_l x9, g_toklen
	ldr  x9, [x9]
	str  x9, [x3, #24]
	adr_l x9, tok_ch
	str  x9, [x3, #32]
	// entry 1: peer (identity)
	adr_l x9, g_identity_hash
	str  x9, [x3, #40]
	adr_l x9, ta_peer
	str  x9, [x3, #48]
	adr_l x9, b_peerdata
	str  x9, [x3, #56]
	adr_l x9, g_peerdata_len
	ldr  x9, [x9]
	str  x9, [x3, #64]
	adr_l x9, g_identity_hash
	str  x9, [x3, #72]
	// entry 2: signature
	adr_l x9, sig_ch
	str  x9, [x3, #80]
	adr_l x9, ta_sig
	str  x9, [x3, #88]
	adr_l x9, b_sigdata
	str  x9, [x3, #96]
	adr_l x9, g_sigdlen
	ldr  x9, [x9]
	str  x9, [x3, #104]
	adr_l x9, sig_ch
	str  x9, [x3, #112]
	mov  x0, #3
	adr_l x1, b_incl_tab
	bl   emit_sorted_included
	// frame + write
	adr_l x9, b_ar_env
	sub  x23, x24, x9                // env len
	rev  w9, w23
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_ar_env
	mov  x2, x23
	bl   write_all
	b    .Lauth_ret
.Lauth_bad_nonce:
	mov  x0, #401
	adr_l x1, ec_invalid_nonce
	bl   send_error
	b    .Lauth_ret
.Lauth_bad_pid:
	mov  x0, #401
	adr_l x1, ec_identity_mismatch
	bl   send_error
	b    .Lauth_ret
.Lauth_bad_sig:
	mov  x0, #401
	adr_l x1, ec_auth_failed
	bl   send_error
	b    .Lauth_ret
.Lauth_bad_imp:
	mov  x0, #401
	adr_l x1, ec_identity_mismatch
	bl   send_error
	b    .Lauth_ret
.Lauth_bad_kt:
	mov  x0, #400
	adr_l x1, ec_unsup_kt
	bl   send_error
.Lauth_ret:
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret
// Authorizes the caller with the same §5.2 gate as the get path (401/403 on failure), then
// mints a token whose grants are copied verbatim from params.data.grants (the caller asks for
// the attenuation it wants), grantee = the request author, granter = this peer; signs it and
// returns a 200 system/capability/grant with {token, granter-peer, signature} in included.
	.type build_request_response, %function
build_request_response:
	// x21=exec, x22=grants value ptr, x23=caller cap hash, x24=CBOR cursor (global).
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x21, x22, [sp, #16]
	stp  x23, x24, [sp, #32]
	mov  x21, x0                     // exec
	// authorize: auth-class (401) then capability + grant-scope (403). The handler derived
	// from data.uri is system/capability, op is request — the authenticate-minted floor
	// token grants exactly that, so a legitimately-authenticated caller passes.
	mov  x0, x21
	bl   verify_get_auth
	cbnz x0, .Lrq_ret
	mov  x0, x21
	bl   verify_get_cap
	cbnz x0, .Lrq_ret
	mov  x0, x21
	bl   verify_op_scope
	cbnz x0, .Lrq_ret
	// grantee = request author (33) → g_grantee
	mov  x0, x21
	adr_l x1, k_author
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lrq_malformed
	bl   get_text
	// mcpy(x0=dst, x1=src, x2=len): get_text returns bytes ptr in x0, so route it as src.
	mov  x9, x0                      // src (get_text bytes ptr)
	adr_l x0, g_grantee             // dst
	mov  x1, x9                      // src
	mov  x2, #33
	bl   mcpy
	// requested grants = params.data.grants (raw CBOR array) → g_reqg_ptr/len
	mov  x0, x21
	adr_l x1, ka_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lrq_malformed
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lrq_malformed
	adr_l x9, g_params_data          // params.data — the §5.6 ttl_ms term lives here
	str  x0, [x9]
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lrq_malformed
	mov  x22, x0                     // grants value ptr
	bl   skip_value                  // x0 = end of grants value
	sub  x0, x0, x22                 // grants byte length
	adr_l x9, g_reqg_ptr
	str  x22, [x9]
	adr_l x9, g_reqg_len
	str  x0, [x9]
	// attenuation (§6.2): the requested grants MUST NOT widen scope beyond the caller's
	// token. Resolve the caller's token data (data.capability → included) and require every
	// requested grant to be covered by some caller grant, else 403 capability_denied.
	mov  x0, x21
	adr_l x1, k_capability
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lrq_denied
	bl   get_text
	mov  x23, x0                     // caller cap hash
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lrq_denied
	mov  x1, x23
	bl   included_find_by_key
	cbz  x0, .Lrq_denied
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lrq_denied
	mov  x1, x0                      // caller token data
	adr_l x9, g_caller_td
	str  x0, [x9]
	mov  x0, x22                     // requested grants array value
	bl   grants_attenuated
	cbnz x0, .Lrq_atten_ok
.Lrq_denied:
	mov  x0, #403
	adr_l x1, ec_cap_denied
	bl   send_error
	b    .Lrq_ret
.Lrq_atten_ok:
	// created_at — sampled ONCE. The duration term below is converted against this same
	// instant; sampling again there emits a token whose stated birth and derived expiry are
	// two different instants.
	bl   now_ms
	adr_l x9, g_created
	str  x0, [x9]
	// ---- §6.2 CAP-5 / §5.6 MIN_DEFINED mint ceiling ----
	//
	//   expires_at = MIN_DEFINED( caller_capability.expires_at,   ; ABSOLUTE, enters directly
	//                             created_at + request.ttl_ms )   ; DURATION, converted first
	//
	// `request` mints a ROOT token (parent: null), so §5.6's parent-child attenuation never
	// reaches it — without this clamp, temporal attenuation is the one dimension a requester
	// could escape and policy withdrawal would have no bounded latency. This is NOT an
	// authorization decision: an over-long ttl_ms from a bounded caller MINTS the clamped
	// value and returns 200, and refusing it is non-conformant.
	//
	// The value is reached BY CONSTRUCTION, not by comparison. A `<= caller_exp` check
	// satisfies a strictly weaker test than the one being run — the oracle says so in its own
	// failure text — so there is deliberately no comparison against the caller's expiry here.
	//
	// §5.6's third term, `created_at + policy_entry.ttl_ms`, is structurally absent on this
	// peer: it writes policy entries (§6.2 configure) but never reads one back on the request
	// path, so there is no policy entry in scope to take a ttl from. That is a missing TERM,
	// not a missing rule — MIN_DEFINED over the terms that exist is exactly what it computes.
	adr_l x9, g_exp_have
	str  xzr, [x9]
	adr_l x9, g_expv
	str  xzr, [x9]
	adr_l x9, g_caller_td
	ldr  x0, [x9]
	cbz  x0, .Lrq_ttl
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lrq_ttl
	bl   read_head
	cbnz x1, .Lrq_ttl                // not a uint64 → unusable, not a term
	adr_l x9, g_expv
	str  x2, [x9]
	mov  x9, #1
	adr_l x10, g_exp_have
	str  x9, [x10]
.Lrq_ttl:
	adr_l x9, g_params_data
	ldr  x0, [x9]
	cbz  x0, .Lrq_mint
	adr_l x1, ka_ttl_ms
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lrq_mint
	bl   read_head
	cbnz x1, .Lrq_mint
	adr_l x9, g_created
	ldr  x9, [x9]
	adds x10, x9, x2                 // created_at + ttl_ms, carry set on overflow
	// §5.6 rule 3: a term that does not fit is DROPPED — never wrapped, never saturated.
	// Saturation would manufacture expires_at == 2^64-1, a finite bound no reader can tell
	// from a deliberate one. ttl_ms == 0 is NOT special-cased (rule 2): it falls out as
	// created_at, which is what keeps "expire immediately" from collapsing into the
	// absent / "no bound" spelling.
	b.hs .Lrq_mint
	adr_l x9, g_exp_have
	ldr  x9, [x9]
	cbnz x9, .Lrq_ttl_min
	adr_l x9, g_expv
	str  x10, [x9]
	mov  x9, #1
	adr_l x11, g_exp_have
	str  x9, [x11]
	b    .Lrq_mint
.Lrq_ttl_min:
	adr_l x9, g_expv
	ldr  x11, [x9]
	cmp  x10, x11
	b.hs .Lrq_mint
	str  x10, [x9]
.Lrq_mint:
	// ---- token data {grants:<raw>, grantee, granter, created_at[, expires_at]} ----
	// Canonical key order is length-then-lex, so expires_at sorts AFTER created_at (same
	// length, c < e) and appends cleanly at the end.
	adr_l x24, b_tokdata
	adr_l x9, g_exp_have
	ldr  x1, [x9]
	add  x1, x1, #4
	bl   w_map
	adr_l x0, ka_grants
	bl   w_cstr
	adr_l x9, g_reqg_ptr
	ldr  x1, [x9]
	adr_l x9, g_reqg_len
	ldr  x2, [x9]
	bl   w_raw
	adr_l x0, ka_grantee
	bl   w_cstr
	adr_l x1, g_grantee
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_granter
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_created
	bl   w_cstr
	adr_l x9, g_created
	ldr  x1, [x9]
	bl   w_uint
	adr_l x9, g_exp_have
	ldr  x9, [x9]
	cbz  x9, .Lrq_tokdone
	adr_l x0, ka_expires
	bl   w_cstr
	adr_l x9, g_expv
	ldr  x1, [x9]
	bl   w_uint
.Lrq_tokdone:
	adr_l x9, b_tokdata
	sub  x2, x24, x9                 // token data len
	adr_l x9, g_toklen
	str  x2, [x9]
	// shared tail: hash+sign the token, build the grant, emit the 200 response.
	bl   mint_finish
	b    .Lrq_ret
.Lrq_malformed:
	// §4.9(c) deliver-or-signal: a `request` missing author / params / params.data /
	// params.data.grants used to fall off the end of this function and answer NOTHING,
	// leaving the caller to wait out its own timeout — indistinguishable from a dead peer.
	// The branch was unreachable for as long as the capability gate refused every delegated
	// capability two stages earlier; implementing the §5.5 chain walk is what let a request
	// get this far, which is the standing lesson in the other direction — a wrong denial can
	// also hide a missing ANSWER, not just a missing check.
	mov  x0, #400
	adr_l x1, ec_invalid_params
	bl   send_error
.Lrq_ret:
	ldp  x23, x24, [sp, #32]
	ldp  x21, x22, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// mint_finish — shared token-grant tail (globals-only): given b_tokdata/g_toklen already
// built (and g_grantee consumed into it), compute the token content_hash, Ed25519-sign it as
// this peer, build the system/signature entity + the system/capability/grant result, and emit
// the 200 EXECUTE_RESPONSE with {token, granter-peer, signature} sorted into `included`.
// Used by build_request_response; build_authenticate_response keeps its own inline copy.
	.type mint_finish, %function
mint_finish:
	// x23 = env len (survives write_all), x24 = CBOR cursor (global).
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	stp  x23, x24, [sp, #16]
	// tok_ch = ec_content_hash("system/capability/token", token_data)
	adr_l x0, ta_token
	mov  x1, #23
	adr_l x2, b_tokdata
	adr_l x9, g_toklen
	ldr  x3, [x9]
	adr_l x4, tok_ch
	bl   ec_content_hash
	// tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	adr_l x0, g_seed
	adr_l x1, tok_ch
	mov  x2, #33
	adr_l x3, tok_sig
	bl   ec_ed25519_sign
	// ---- signature entity data {signer,target,algorithm,signature} ----
	adr_l x24, b_sigdata
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_signer
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_target
	bl   w_cstr
	adr_l x1, tok_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_algo
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_sig
	bl   w_cstr
	adr_l x1, tok_sig
	mov  x2, #64
	bl   w_bstr
	adr_l x9, b_sigdata
	sub  x2, x24, x9                 // sig data len
	adr_l x9, g_sigdlen
	str  x2, [x9]
	adr_l x0, ta_sig
	mov  x1, #16
	adr_l x2, b_sigdata
	adr_l x9, g_sigdlen
	ldr  x3, [x9]
	adr_l x4, sig_ch
	bl   ec_content_hash
	// ---- grant result data {token: tok_ch} ----
	adr_l x24, b_grantdata
	mov  x1, #1
	bl   w_map
	adr_l x0, ka_token
	bl   w_cstr
	adr_l x1, tok_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x9, b_grantdata
	sub  x2, x24, x9                 // grant data len
	adr_l x9, g_grlen
	str  x2, [x9]
	adr_l x0, ta_grant
	mov  x1, #23
	adr_l x2, b_grantdata
	adr_l x9, g_grlen
	ldr  x3, [x9]
	adr_l x4, grant_ch
	bl   ec_content_hash
	// ---- response data {result, status, request_id} ----
	adr_l x24, b_ar_resp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	adr_l x0, ta_grant
	adr_l x1, b_grantdata
	adr_l x9, g_grlen
	ldr  x2, [x9]
	adr_l x3, grant_ch
	bl   w_entity
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_ar_resp
	sub  x2, x24, x9                 // response data len
	adr_l x9, g_ardlen
	str  x2, [x9]
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x3, [x9]
	adr_l x4, resp_ch2
	bl   ec_content_hash
	// ---- envelope {root, included} ----
	adr_l x24, b_ar_env
	mov  x1, #2
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x2, [x9]
	adr_l x3, resp_ch2
	bl   w_entity
	adr_l x0, ka_included
	bl   w_cstr
	adr_l x3, b_incl_tab            // table base (x3, since x0/x1/x2 feed emit_sorted_included)
	// entry 0: token
	adr_l x9, tok_ch
	str  x9, [x3, #0]
	adr_l x9, ta_token
	str  x9, [x3, #8]
	adr_l x9, b_tokdata
	str  x9, [x3, #16]
	adr_l x10, g_toklen
	ldr  x9, [x10]
	str  x9, [x3, #24]
	adr_l x9, tok_ch
	str  x9, [x3, #32]
	// entry 1: peer (identity)
	adr_l x9, g_identity_hash
	str  x9, [x3, #40]
	adr_l x9, ta_peer
	str  x9, [x3, #48]
	adr_l x9, b_peerdata
	str  x9, [x3, #56]
	adr_l x10, g_peerdata_len
	ldr  x9, [x10]
	str  x9, [x3, #64]
	adr_l x9, g_identity_hash
	str  x9, [x3, #72]
	// entry 2: signature
	adr_l x9, sig_ch
	str  x9, [x3, #80]
	adr_l x9, ta_sig
	str  x9, [x3, #88]
	adr_l x9, b_sigdata
	str  x9, [x3, #96]
	adr_l x10, g_sigdlen
	ldr  x9, [x10]
	str  x9, [x3, #104]
	adr_l x9, sig_ch
	str  x9, [x3, #112]
	mov  x0, #3
	adr_l x1, b_incl_tab
	bl   emit_sorted_included
	// frame + write
	adr_l x9, b_ar_env
	sub  x23, x24, x9               // env len
	rev  w9, w23                    // big-endian length prefix
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_ar_env
	mov  x2, x23
	bl   write_all
	ldp  x23, x24, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret
// store_put's arena/index caps are defined by the data fragment (10_data1.s) that precedes
// this one in the concatenated dispatch.s. They are used here as bare immediates, so guard-
// define them for the isolated per-fragment check; when 10_data1.s already defined them the
// .ifndef skips these copies (no effect on the real build).
	.ifndef STORE_MAX
	.equ STORE_MAX,   8192
	.endif
	.ifndef STORE_ARENA_CAP
	.equ STORE_ARENA_CAP, 67108864
	.endif

// send_error(x0=status, x1=code_cstr) — emit a status EXECUTE_RESPONSE with a
// system/protocol/error {code} result. No `included`.
	.type send_error, %function
send_error:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]
	mov  x21, x0                     // status
	mov  x22, x1                     // code cstr
	adr_l x24, b_err
	mov  x1, #1
	bl   w_map
	adr_l x0, k_code
	bl   w_cstr
	mov  x0, x22
	bl   w_cstr
	adr_l x9, b_err
	sub  x23, x24, x9                // err data len
	adr_l x0, t_error
	mov  x1, #21
	adr_l x2, b_err
	mov  x3, x23
	adr_l x4, err_ch
	bl   ec_content_hash
	adr_l x24, b_er_resp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	adr_l x0, t_error
	adr_l x1, b_err
	mov  x2, x23
	adr_l x3, err_ch
	bl   w_entity
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, x21
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_er_resp
	sub  x23, x24, x9                // resp data len
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_er_resp
	mov  x3, x23
	adr_l x4, er_resp_ch
	bl   ec_content_hash
	adr_l x24, b_er_env
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_er_resp
	mov  x2, x23
	adr_l x3, er_resp_ch
	bl   w_entity
	adr_l x9, b_er_env
	sub  x23, x24, x9                // env len
	rev  w9, w23
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_er_env
	mov  x2, x23
	bl   write_all
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// serve_tree_get(x0 = exec data map ptr) — resolve resource.targets[0] against the
// embedded read-only type/handler store; 200 with the stored entity, else 404.
// =====================================================================
	.type serve_tree_get, %function
// chain_depth_check(x0 = exec data map) -> x0 = 0 ok, 1 rejected (400 chain_depth_exceeded).
// §9.1/§4.10(b) resource floor: follow the presented capability's `parent` chain through
// `included`; a chain deeper than 64 delegations is rejected before the authority walk. A
// cyclic chain terminates the same way (depth passes 64). Server-minted tokens carry no
// parent (depth 0), so the type_system cohort is untouched.
	.type chain_depth_check, %function
chain_depth_check:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x22, x0                    // exec
	adr_l x1, k_capability
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lcd_ok                // no capability → nothing to bound
	bl   get_text
	mov  x21, x0                    // cur = capability hash ptr (33)
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lcd_ok
	mov  x20, x0                    // included
	mov  x19, #0                    // depth = 0
.Lcd_loop:
	mov  x0, x20
	mov  x1, x21
	bl   included_find_by_key
	cbz  x0, .Lcd_ok               // chain ends (unresolvable) → depth within bound
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lcd_ok
	adr_l x1, ka_parent
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lcd_ok              // root reached (no parent) → within bound
	bl   get_text
	mov  x21, x0                  // cur = parent hash
	add  x19, x19, #1
	cmp  x19, #64
	b.ls .Lcd_loop               // ≤64 delegations → keep walking
	mov  x0, #400
	adr_l x1, ec_chain_depth
	bl   send_error
	mov  x0, #1
	b    .Lcd_ret
.Lcd_ok:
	mov  x0, #0
.Lcd_ret:
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

	.type serve_tree_get, %function
serve_tree_get:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x21, x0                    // exec data map
	// §9.1/§4.10(b) resource floor — reject an over-deep delegation chain (400) up front,
	// before the authority walk, so a maliciously deep chain can't force unbounded work.
	mov  x0, x21
	bl   chain_depth_check
	cbnz x0, .Lstg_done            // 400 chain_depth_exceeded already sent
	// §5.2 auth-class gate — reject unauthenticated/tampered requests (401) before serving.
	mov  x0, x21
	bl   verify_get_auth          // x0 = exec
	cbnz x0, .Lstg_done           // rejected; 401 already sent
	// §5.2 capability-class gate (403) — token present/bound/signed.
	mov  x0, x21
	bl   verify_get_cap
	cbnz x0, .Lstg_done           // rejected; 403 already sent
	// §5.2 grant-scope gate (403 default-deny) — token must permit op×handler×resource.
	mov  x0, x21
	bl   verify_get_scope
	cbnz x0, .Lstg_done           // rejected; 403 already sent
	// resource = map_find(exec, "resource", 8)
	mov  x0, x21
	adr_l x1, k_resource
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lstg_404
	// targets = map_find(resource, "targets", 7)
	adr_l x1, k_targets
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lstg_404
	// x0 = targets array value; read head, require ≥1 element
	bl   read_head                // x0=after-head, x1=major(4), x2=count
	cbz  x2, .Lstg_404
	// first element is a text string → ptr,len
	bl   get_text                 // x0=strptr, x2=strlen
	mov  x19, x0                  // raw target ptr
	mov  x20, x2                  // raw target len
	// §"invalid_path" reject (dot-relative / empty-segment / NUL).
	mov  x1, x19
	mov  x3, x20
	bl   path_valid
	cbz  x0, .Lstg_invalid
	// empty target (root) or trailing '/' → listing over the store (§tree get listing).
	cbz  x20, .Lstg_listing       // empty = root listing
	add  x9, x19, x20
	ldrb w9, [x9, #-1]            // last byte
	cmp  w9, #0x2f                // '/'?
	b.ne .Lstg_point
.Lstg_listing:
	mov  x0, x19
	mov  x1, x20
	bl   serve_tree_listing       // emits its own 200/404
	b    .Lstg_done
.Lstg_point:
	// §1.4 canonicalize for the write-store key; the read-only typestore keeps raw keys.
	mov  x1, x19
	mov  x3, x20
	bl   canon_path               // x0=canon ptr, x2=canon len
	mov  x1, x0
	mov  x3, x2
	bl   store_get                // -> x0=blob|0, x2=len
	cbnz x0, .Lstg_send
	mov  x1, x19                  // raw target for the read-only typestore
	mov  x3, x20
	bl   typestore_lookup         // -> x0=blobptr|0, x2=bloblen
	cbz  x0, .Lstg_404
.Lstg_send:
	mov  x1, x2
	bl   send_get_ok
	b    .Lstg_done
.Lstg_invalid:
	mov  x0, #400
	adr_l x1, ec_invalid_path
	bl   send_error
	b    .Lstg_done
.Lstg_404:
	mov  x0, #404
	adr_l x1, ec_not_found
	bl   send_error
.Lstg_done:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// typestore_lookup(x1 = target ptr, x3 = target len) -> x0 = blob ptr|0, x2 = blob len.
// Linear scan of the generated type_table (the core floor, currently 58 entries;
// the count is read from type_table_count, never assumed); exact string match on the path
// (the listing path "system/type/" carries its trailing slash, so it matches verbatim too).
	.type typestore_lookup, %function
typestore_lookup:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x21, x1                    // target ptr
	mov  x22, x3                    // target len
	adr_l x19, type_table
	adr_l x9, type_table_count
	ldr  x20, [x9]
.Ltl_loop:
	cbz  x20, .Ltl_none
	ldr  x9, [x19, #8]             // entry.path_len
	cmp  x9, x22
	b.ne .Ltl_next
	ldr  x0, [x19]                // entry.path_ptr
	mov  x1, x21
	mov  x2, x22
	bl   memeq
	cbnz x0, .Ltl_found
.Ltl_next:
	add  x19, x19, #32
	sub  x20, x20, #1
	b    .Ltl_loop
.Ltl_found:
	ldr  x0, [x19, #16]           // entry.blob_ptr
	ldr  x2, [x19, #24]           // entry.blob_len
	b    .Ltl_ret
.Ltl_none:
	mov  x0, #0
	mov  x2, #0
.Ltl_ret:
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// send_get_ok(x0 = entity blob ptr, x1 = entity blob len) — emit a 200 EXECUTE_RESPONSE
// whose `result` is the pre-serialized stored entity, copied verbatim (w_raw). Mirrors
// send_error's envelope construction.
	.type send_get_ok, %function
send_get_ok:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x24, [sp, #32]
	mov  x19, x0                    // blob ptr
	mov  x20, x1                    // blob len
	// ---- data map {result:<blob>, status:200, request_id:<rid>} ----
	adr_l x24, b_get_data
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	mov  x1, x19
	mov  x2, x20
	bl   w_raw
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_get_data
	sub  x21, x24, x9              // x21 = data len
	// content_hash of the response entity
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_get_data
	mov  x3, x21
	adr_l x4, get_data_ch
	bl   ec_content_hash
	// ---- envelope {root: <resp entity>} ----
	adr_l x24, b_get_env
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_get_data
	mov  x2, x21
	adr_l x3, get_data_ch
	bl   w_entity
	// ---- frame (4-byte BE len) + send ----
	adr_l x9, b_get_env
	sub  x21, x24, x9
	rev  w9, w21
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_get_env
	mov  x2, x21
	bl   write_all
	ldp  x21, x24, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// =====================================================================
// A-ASM-011 — per-fork write store (path→entity). store_idx is an array of 32-byte entries
// [0]=path_ptr [8]=path_len [16]=blob_ptr [24]=blob_len, pointing into store_arena where the
// bytes are copied out of the per-frame-reused b_req so they persist across the connection.
// =====================================================================

// store_get(x1 = path ptr, x3 = path len) -> x0 = blob ptr|0, x2 = blob len.
// Preserves x1/x3 so the caller can fall through to the read-only typestore_lookup.
	.type store_get, %function
store_get:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x21, x1                    // path ptr
	mov  x22, x3                    // path len
	adr_l x19, store_idx
	adr_l x9, store_count
	ldr  x20, [x9]
.Lsg_loop:
	cbz  x20, .Lsg_none
	ldr  x9, [x19, #8]             // entry.path_len
	cmp  x9, x22
	b.ne .Lsg_next
	ldr  x0, [x19]                // entry.path_ptr
	mov  x1, x21
	mov  x2, x22
	bl   memeq
	cbnz x0, .Lsg_found
.Lsg_next:
	add  x19, x19, #32
	sub  x20, x20, #1
	b    .Lsg_loop
.Lsg_found:
	ldr  x0, [x19, #16]           // blob ptr
	ldr  x2, [x19, #24]           // blob len
	b    .Lsg_ret
.Lsg_none:
	mov  x0, #0
	mov  x2, #0
.Lsg_ret:
	mov  x1, x21                  // restore path ptr/len for the caller's fallback
	mov  x3, x22
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// store_put(x0 = path ptr, x1 = path len, x2 = blob ptr, x3 = blob len).
// Overwrites an existing binding in place (new blob appended to the arena), else appends a
// new entry. x25 holds the scan counter across memeq (memeq never touches x25).
	.type store_put, %function
store_put:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x19, x0                    // path ptr
	mov  x20, x1                    // path len
	mov  x21, x2                    // blob ptr
	mov  x22, x3                    // blob len
	// arena capacity guard — never write past store_arena (would corrupt neighbouring .bss).
	adr_l x9, store_used
	ldr  x9, [x9]
	add  x9, x9, x20
	add  x9, x9, x22
	mov  x10, #STORE_ARENA_CAP
	cmp  x9, x10
	b.hi .Lsp_ret
	adr_l x23, store_idx
	adr_l x9, store_count
	ldr  x25, [x9]
.Lsp_scan:
	cbz  x25, .Lsp_new
	ldr  x9, [x23, #8]            // entry.path_len
	cmp  x9, x20
	b.ne .Lsp_scan_next
	ldr  x0, [x23]
	mov  x1, x19
	mov  x2, x20
	bl   memeq
	cbnz x0, .Lsp_overwrite
.Lsp_scan_next:
	add  x23, x23, #32
	sub  x25, x25, #1
	b    .Lsp_scan
.Lsp_overwrite:
	// x23 = matching entry — append new blob to the arena, repoint the entry.
	adr_l x0, store_arena
	adr_l x9, store_used
	ldr  x9, [x9]
	add  x0, x0, x9
	str  x0, [x23, #16]          // entry.blob_ptr = dst
	str  x22, [x23, #24]         // entry.blob_len
	mov  x1, x21
	mov  x2, x22
	bl   mcpy
	adr_l x9, store_used
	ldr  x10, [x9]
	add  x10, x10, x22
	str  x10, [x9]
	b    .Lsp_ret
.Lsp_new:
	adr_l x9, store_count
	ldr  x9, [x9]
	mov  x10, #STORE_MAX
	cmp  x9, x10                 // index-full guard — drop rather than overrun store_idx
	b.hs .Lsp_ret
	lsl  x9, x9, #5              // *32
	adr_l x23, store_idx
	add  x23, x23, x9            // x23 = new entry slot
	adr_l x0, store_arena
	adr_l x9, store_used
	ldr  x9, [x9]
	add  x0, x0, x9             // dst = arena + used
	str  x0, [x23]             // entry.path_ptr
	str  x20, [x23, #8]        // entry.path_len
	mov  x1, x19               // path src
	mov  x2, x20
	bl   mcpy                   // x0 = dst + path_len = blob dst
	str  x0, [x23, #16]        // entry.blob_ptr
	str  x22, [x23, #24]       // entry.blob_len
	mov  x1, x21               // blob src
	mov  x2, x22
	bl   mcpy
	adr_l x9, store_used
	ldr  x10, [x9]
	add  x10, x10, x20
	add  x10, x10, x22
	str  x10, [x9]
	adr_l x9, store_count
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
.Lsp_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// canon_path(x1 = path ptr, x3 = path len) -> x0 = canon ptr, x2 = canon len.
// §1.4 universal address space: a peer-relative path `foo` canonicalizes to the absolute
// `/{localPeerID}/foo`; an already-absolute `/…` path (incl. foreign namespaces) is verbatim.
// Relative results are built into b_canon; absolute results alias the input.
	.type canon_path, %function
canon_path:
	cbz  x3, .Lcp_asis
	ldrb w9, [x1]                   // leading byte
	cmp  w9, #0x2f                  // '/' → already absolute
	b.eq .Lcp_asis
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x1                    // path ptr
	mov  x20, x3                    // path len
	adr_l x21, b_canon
	mov  w9, #0x2f                  // '/'
	strb w9, [x21]
	add  x21, x21, #1
	mov  x0, x21
	adr_l x1, g_peerid
	adr_l x9, g_peerid_len
	ldr  x2, [x9]
	bl   mcpy                       // x0 = dst end
	mov  x21, x0
	mov  w9, #0x2f                  // '/'
	strb w9, [x21]
	add  x21, x21, #1
	mov  x0, x21
	mov  x1, x19
	mov  x2, x20
	bl   mcpy                       // x0 = end of canon
	adr_l x9, b_canon
	sub  x2, x0, x9                 // x2 = canon len
	adr_l x0, b_canon              // x0 = canon ptr
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret
.Lcp_asis:
	mov  x0, x1
	mov  x2, x3
	ret

// path_valid(x1 = path ptr, x3 = path len) -> x0 = 1 valid / 0 invalid.
// §"invalid_path": rejects a NUL byte, an empty non-leading segment ("//"), and any "."/".."
// segment (dot-relative). A single trailing '/' (listing) and a single leading '/' (absolute)
// are allowed; Unicode segments are accepted (only the byte rules above apply).
	.type path_valid, %function
path_valid:
	// §1.4: caller-supplied paths are peer-relative; a leading '/' means an absolute
	// /{peerID}/… address, so the first segment must be peer-id-length. A short leading
	// segment ("/system/…") is a mis-scoped caller path → invalid_path.
	cbz  x3, .Lpv_body
	ldrb w9, [x1]
	cmp  w9, #0x2f
	b.ne .Lpv_body
	mov  x4, #1
.Lpv_fs:
	cmp  x4, x3
	b.hs .Lpv_fsdone
	ldrb w9, [x1, x4]
	cmp  w9, #0x2f
	b.eq .Lpv_fsdone
	add  x4, x4, #1
	b    .Lpv_fs
.Lpv_fsdone:
	sub  x4, x4, #1                 // first-segment length
	cmp  x4, #32
	b.lo .Lpv_bad
.Lpv_body:
	mov  x4, #0                     // i
	mov  x5, #0                     // seg_start
.Lpv_loop:
	cmp  x4, x3
	b.hs .Lpv_final
	ldrb w9, [x1, x4]
	cbz  w9, .Lpv_bad              // NUL
	cmp  w9, #0x2f                 // '/'
	b.ne .Lpv_next
	sub  x10, x4, x5              // seg_len
	cbnz x10, .Lpv_checkdot
	cbnz x5, .Lpv_bad            // empty segment: OK only when leading (seg_start==0)
	b    .Lpv_advance
.Lpv_checkdot:
	cmp  x10, #1
	b.ne .Lpv_checkdd
	ldrb w9, [x1, x5]
	cmp  w9, #0x2e                // "."
	b.eq .Lpv_bad
	b    .Lpv_advance
.Lpv_checkdd:
	cmp  x10, #2
	b.ne .Lpv_advance
	ldrb w9, [x1, x5]
	cmp  w9, #0x2e
	b.ne .Lpv_advance
	add  x9, x5, #1
	ldrb w9, [x1, x9]
	cmp  w9, #0x2e               // ".."
	b.eq .Lpv_bad
.Lpv_advance:
	add  x5, x4, #1
.Lpv_next:
	add  x4, x4, #1
	b    .Lpv_loop
.Lpv_final:
	sub  x10, x3, x5              // final seg len
	cbz  x10, .Lpv_ok            // trailing '/' or empty → allow
	cmp  x10, #1
	b.ne .Lpv_fdd
	ldrb w9, [x1, x5]
	cmp  w9, #0x2e
	b.eq .Lpv_bad
	b    .Lpv_ok
.Lpv_fdd:
	cmp  x10, #2
	b.ne .Lpv_ok
	ldrb w9, [x1, x5]
	cmp  w9, #0x2e
	b.ne .Lpv_ok
	add  x9, x5, #1
	ldrb w9, [x1, x9]
	cmp  w9, #0x2e
	b.eq .Lpv_bad
.Lpv_ok:
	mov  x0, #1
	ret
.Lpv_bad:
	mov  x0, #0
	ret

// cas_check(x0 = params.data map, x1 = path ptr, x2 = path len) -> x0 = 0 ok / 1 conflict.
// §"tree put" CAS: expected_hash absent → unconditional. all-zero(33B) → path must be ABSENT
// (create). nonzero → path must exist and its entity's content_hash must equal expected_hash.
	.type cas_check, %function
cas_check:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x21, x1                    // path ptr
	mov  x22, x2                    // path len
	mov  x20, x0                    // params.data
	mov  x0, x20
	adr_l x1, k_expected
	mov  x2, #13
	bl   map_find
	cbz  x0, .Lcas_ok             // absent → unconditional put
	bl   get_text                // x0=exp ptr, x2=exp len
	mov  x23, x0                 // expected hash ptr
	mov  x3, x2                  // exp len
	mov  x19, #0                  // OR-accumulator (0 ⇒ all-zero)
	mov  x9, #0
.Lcas_zscan:
	cmp  x9, x3
	b.hs .Lcas_zdone
	ldrb w10, [x23, x9]
	orr  w19, w19, w10
	add  x9, x9, #1
	b    .Lcas_zscan
.Lcas_zdone:
	mov  x1, x21
	mov  x3, x22
	bl   store_get               // x0=cur blob|0, x2=len
	cbnz x19, .Lcas_nonzero
	// expected all-zero → require ABSENT
	cbnz x0, .Lcas_conflict
	b    .Lcas_ok
.Lcas_nonzero:
	// require PRESENT with matching content_hash
	cbz  x0, .Lcas_conflict
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lcas_conflict
	bl   get_text                // x0=cur chash ptr
	mov  x1, x23
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lcas_conflict
	b    .Lcas_ok
.Lcas_conflict:
	mov  x0, #1
	b    .Lcas_ret
.Lcas_ok:
	mov  x0, #0
.Lcas_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret
// =====================================================================
// serve_tree_put(x0 = exec data map) — §5.2-gated write of params.data.entity at
// resource.targets[0] into the per-fork store; 200 system/tree/put-result{content_hash}.
// x20=exec, x21=path ptr, x22=path len, x23=params.data map, x19=entity blob start.
// =====================================================================
	.type serve_tree_put, %function
serve_tree_put:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x20, x0                     // exec
	mov  x0, x20
	bl   chain_depth_check
	cbnz x0, .Lstp_done
	mov  x0, x20
	bl   verify_get_auth
	cbnz x0, .Lstp_done
	mov  x0, x20
	bl   verify_get_cap
	cbnz x0, .Lstp_done
	mov  x0, x20
	bl   verify_get_scope
	cbnz x0, .Lstp_done
	// path = resource.targets[0]
	mov  x0, x20
	adr_l x1, k_resource
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lstp_400
	adr_l x1, k_targets
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lstp_400
	bl   read_head                   // x2 = count
	cbz  x2, .Lstp_400
	bl   get_text                    // x0=path ptr, x2=path len
	mov  x21, x0
	mov  x22, x2
	// §"invalid_path" reject (dot-relative / empty-segment / NUL) before any write.
	mov  x1, x21
	mov  x3, x22
	bl   path_valid
	cbz  x0, .Lstp_invalid
	// §1.4 canonicalize the store key (peer-relative → /{localPeerID}/…).
	mov  x1, x21
	mov  x3, x22
	bl   canon_path                  // x0=canon ptr, x2=canon len
	mov  x21, x0
	mov  x22, x2
	// entity = params.data.entity
	mov  x0, x20
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lstp_400
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lstp_400
	mov  x23, x0                     // params.data map
	adr_l x1, k_entity
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lstp_400
	mov  x19, x0                     // entity blob start (into b_req)
	// CAS pre-check
	mov  x0, x23
	mov  x1, x21
	mov  x2, x22
	bl   cas_check
	cbnz x0, .Lstp_409
	// blob len = skip_value(entity) - entity
	mov  x0, x19
	bl   skip_value                  // x0 = entity end
	sub  x0, x0, x19                 // x0 = blob len
	// store_put(path, pathlen, blob, bloblen)
	mov  x3, x0                      // blob len
	mov  x0, x21                     // path ptr
	mov  x1, x22                     // path len
	mov  x2, x19                     // blob ptr
	bl   store_put
	// put-result content_hash = the stored entity's own content_hash field (§1.8 recompute-equal)
	mov  x0, x19
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lstp_400
	bl   get_text                    // x0 = chash ptr (33B)
	bl   send_put_ok
	b    .Lstp_done
.Lstp_409:
	mov  x0, #409
	adr_l x1, ec_hash_mismatch
	bl   send_error
	b    .Lstp_done
.Lstp_invalid:
	mov  x0, #400
	adr_l x1, ec_invalid_path
	bl   send_error
	b    .Lstp_done
.Lstp_400:
	mov  x0, #400
	adr_l x1, ec_unexpected_params
	bl   send_error
.Lstp_done:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// send_put_ok(x0 = 33-byte content_hash ptr) — 200 EXECUTE_RESPONSE whose result is a
// freshly-built system/tree/put-result{content_hash} entity. Mirrors send_error's envelope.
// x20=chash ptr, x21=prd data len, x22=resp data len; cursor is x24 (x86 r15).
	.type send_put_ok, %function
send_put_ok:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x20, x21, [sp, #16]
	stp  x22, x24, [sp, #32]
	mov  x20, x0                     // chash ptr (33B)
	// ---- put-result inner data {content_hash:<33B>} ----
	adr_l x24, b_prd_data
	mov  x1, #1
	bl   w_map
	adr_l x0, k_chash
	bl   w_cstr
	mov  x1, x20
	mov  x2, #33
	bl   w_bstr
	adr_l x9, b_prd_data
	sub  x21, x24, x9                // x21 = prd data len
	adr_l x0, t_put_result
	mov  x1, #22
	adr_l x2, b_prd_data
	mov  x3, x21
	adr_l x4, prd_ch
	bl   ec_content_hash
	// ---- response data {result:<put-result entity>, status:200, request_id} ----
	adr_l x24, b_put_resp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	adr_l x0, t_put_result
	adr_l x1, b_prd_data
	mov  x2, x21
	adr_l x3, prd_ch
	bl   w_entity
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_put_resp
	sub  x22, x24, x9                // x22 = resp data len
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_put_resp
	mov  x3, x22
	adr_l x4, put_resp_ch
	bl   ec_content_hash
	// ---- envelope {root:<resp entity>} ----
	adr_l x24, b_put_env
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_put_resp
	mov  x2, x22
	adr_l x3, put_resp_ch
	bl   w_entity
	// ---- frame + send ----
	adr_l x9, b_put_env
	sub  x22, x24, x9                // x22 = envelope len
	rev  w9, w22                     // 4-byte big-endian frame length
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_put_env
	mov  x2, x22
	bl   write_all
	ldp  x22, x24, [sp, #32]
	ldp  x20, x21, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// system/handler register / unregister (writes handler entities to the per-fork store).
// =====================================================================

// find_raw(x0=map, x1=key cstr, x2=key len) -> x0 = value ptr|0, x2 = value byte-length.
// Returns the verbatim CBOR span of a map value (head + body), for embedding via w_raw.
// x20 = value ptr (callee-saved across skip_value).
	.type find_raw, %function
find_raw:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x20, [sp, #16]
	bl   map_find
	cbz  x0, .Lfr_none
	mov  x20, x0
	bl   skip_value                  // x0 = end
	sub  x2, x0, x20                 // value byte-length
	mov  x0, x20
	ldr  x20, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret
.Lfr_none:
	mov  x0, #0
	mov  x2, #0
	ldr  x20, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// mk_entity(x0=type cstr, x1=type len, x2=data ptr, x3=data len, x4=chash out buf) ->
// x0 = entity byte-length. Hashes the data, writes the {data,type,content_hash} entity into
// the shared b_ent_scratch (reg_store copies it out immediately after).
// x20=type cstr, x21=type len, x19=data ptr, x22=data len; cursor is x24 (x86 r15).
	.type mk_entity, %function
mk_entity:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x24, [sp, #48]
	mov  x20, x0                     // type cstr
	mov  x21, x1                     // type len
	mov  x19, x2                     // data ptr
	mov  x22, x3                     // data len
	adr_l x9, g_chbuf
	str  x4, [x9]
	mov  x0, x20
	mov  x1, x21
	mov  x2, x19
	mov  x3, x22
	adr_l x9, g_chbuf
	ldr  x4, [x9]
	bl   ec_content_hash
	adr_l x24, b_ent_scratch
	mov  x0, x20                     // type cstr
	mov  x1, x19                     // data ptr
	mov  x2, x22                     // data len
	adr_l x9, g_chbuf
	ldr  x3, [x9]                    // chash ptr
	bl   w_entity
	adr_l x9, b_ent_scratch
	sub  x0, x24, x9                 // entlen
	ldr  x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// reg_store(x0=path ptr, x1=path len, x2=blob ptr, x3=blob len) — canonicalize the path
// (§1.4) and store the entity blob under it. x22=blob ptr, x23=blob len.
	.type reg_store, %function
reg_store:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x22, x23, [sp, #16]
	mov  x22, x2                     // blob ptr
	mov  x23, x3                     // blob len
	mov  x3, x1                      // path len (canon_path wants rcx→x3)
	mov  x1, x0                      // path ptr (canon_path wants rsi→x1)
	bl   canon_path                  // x0=canon ptr, x2=canon len
	// store_put(path, pathlen, blob, bloblen)
	mov  x1, x2                      // canon len → pathlen
	// x0 already = canon ptr
	mov  x2, x22                     // blob ptr
	mov  x3, x23                     // blob len
	bl   store_put
	ldp  x22, x23, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// pcat(x0=prefix ptr, x1=prefix len, x2=seg ptr, x3=seg len) -> x0=b_hpath ptr, x2=len.
// x19=prefix ptr, x20=prefix len, x21=seg ptr, x22=seg len.
	.type pcat, %function
pcat:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x19, x0                     // prefix ptr
	mov  x20, x1                     // prefix len
	mov  x21, x2                     // seg ptr
	mov  x22, x3                     // seg len
	adr_l x0, b_hpath
	mov  x1, x19
	mov  x2, x20
	bl   mcpy                        // x0 = dst + preflen
	// mcpy(dst, src, len): x0 already = dst cursor
	mov  x1, x21
	mov  x2, x22
	bl   mcpy
	adr_l x0, b_hpath
	add  x2, x20, x22                // total len
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// hexenc(x0=src 33-byte ptr, x1=dst ptr) — write 66 lowercase hex chars. Leaf.
	.type hexenc, %function
hexenc:
	mov  x9, #0                      // index
.Lhx:
	cmp  x9, #33
	b.hs .Lhx_done
	ldrb w10, [x0, x9]               // byte
	lsr  w11, w10, #4                // high nibble
	adr_l x12, hexchars
	ldrb w11, [x12, x11]
	strb w11, [x1]
	add  x1, x1, #1
	ldrb w10, [x0, x9]
	and  w10, w10, #0xf              // low nibble
	adr_l x12, hexchars
	ldrb w10, [x12, x10]
	strb w10, [x1]
	add  x1, x1, #1
	add  x9, x9, #1
	b    .Lhx
.Lhx_done:
	ret

// serve_register(x0 = exec data map) — §5.2-gated system/handler register. Writes 4 entities
// to the store (interface, handler, capability token, signature) and returns 200
// system/handler/register-result {grant, pattern}.
// x20=exec, x21=params.data, x22=manifest map; cursor is x24 (x86 r15).
	.type serve_register, %function
serve_register:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x24, [sp, #48]
	mov  x20, x0                     // exec
	mov  x0, x20
	bl   chain_depth_check
	cbnz x0, .Lsr_done
	mov  x0, x20
	bl   verify_get_auth
	cbnz x0, .Lsr_done
	mov  x0, x20
	bl   verify_get_cap
	cbnz x0, .Lsr_done
	mov  x0, x20
	bl   verify_get_scope
	cbnz x0, .Lsr_done
	// params.data → x21
	mov  x0, x20
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsr_400
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lsr_400
	mov  x21, x0                     // params.data
	// manifest → x22
	mov  x0, x21
	adr_l x1, k_manifest
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lsr_400
	mov  x22, x0                     // manifest map
	// pattern content → g_hpat
	mov  x0, x22
	adr_l x1, k_pattern
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lsr_400
	bl   get_text
	adr_l x9, g_hpat_ptr
	str  x0, [x9]
	adr_l x9, g_hpat_len
	str  x2, [x9]
	// ── §6.2 reserved-pattern guard ─────────────────────────────────────
	// user-installed handlers MUST NOT register at system/* paths. Runs
	// right after the pattern is extracted but BEFORE any of the five
	// normative writes below (interface/handler/token/signature/response).
	// Reserved iff pattern == "system" (len 6, exact) or pattern starts
	// with "system/" (len >= 7, prefix). mcmp_lex is a leaf (x0-x2/x9/x10
	// only); x19 survives the call unsaved.
	adr_l x9, g_hpat_len
	ldr  x19, [x9]                  // pattern len
	cmp  x19, #7
	b.lt .Lsr_pat_chk6
	adr_l x9, g_hpat_ptr
	ldr  x0, [x9]
	adr_l x1, p_sys_slash
	mov  x2, #7
	bl   mcmp_lex
	cbz  w0, .Lsr_reserved
	b    .Lsr_pat_ok
.Lsr_pat_chk6:
	cmp  x19, #6
	b.ne .Lsr_pat_ok
	adr_l x9, g_hpat_ptr
	ldr  x0, [x9]
	adr_l x1, p_sys_bare
	mov  x2, #6
	bl   mcmp_lex
	cbnz w0, .Lsr_pat_ok
.Lsr_reserved:
	mov  x0, #403
	adr_l x1, ec_forbidden_pattern
	bl   send_error
	b    .Lsr_done
.Lsr_pat_ok:
	// interface store path = "system/handler/" + pattern → save into b_ipath
	adr_l x0, p_hnd_slash
	mov  x1, #15
	adr_l x9, g_hpat_ptr
	ldr  x2, [x9]
	adr_l x9, g_hpat_len
	ldr  x3, [x9]
	bl   pcat                        // x0=b_hpath, x2=len
	adr_l x9, g_ipath_len
	str  x2, [x9]
	mov  x1, x0                      // src = b_hpath
	adr_l x0, b_ipath                // dst
	// x2 already = len
	bl   mcpy

	// ===== 1. interface entity {name, pattern, operations} =====
	adr_l x24, b_iface_data
	mov  x1, #3
	bl   w_map
	adr_l x0, k_name
	bl   w_cstr
	mov  x0, x22
	adr_l x1, k_name
	mov  x2, #4
	bl   find_raw                    // x0=ptr, x2=len
	mov  x1, x0
	bl   w_raw
	adr_l x0, k_pattern
	bl   w_cstr
	mov  x0, x22
	adr_l x1, k_pattern
	mov  x2, #7
	bl   find_raw
	mov  x1, x0
	bl   w_raw
	adr_l x0, ka_operations
	bl   w_cstr
	mov  x0, x22
	adr_l x1, ka_operations
	mov  x2, #10
	bl   find_raw
	mov  x1, x0
	bl   w_raw
	adr_l x9, b_iface_data
	sub  x3, x24, x9
	adr_l x9, g_tmplen
	str  x3, [x9]
	adr_l x0, t_iface
	mov  x1, #24
	adr_l x2, b_iface_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, iface_ch
	bl   mk_entity                   // x0 = entlen; blob in b_ent_scratch
	// store at b_ipath
	mov  x3, x0                      // blob len
	adr_l x0, b_ipath                // path ptr
	adr_l x9, g_ipath_len
	ldr  x1, [x9]                    // path len
	adr_l x2, b_ent_scratch          // blob ptr
	bl   reg_store

	// ===== 2. handler entity {interface, internal_scope, expression_path} =====
	adr_l x24, b_hdlr_data
	mov  x1, #3
	bl   w_map
	adr_l x0, k_interface
	bl   w_cstr
	adr_l x1, b_ipath
	adr_l x9, g_ipath_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x0, k_internal_scope
	bl   w_cstr
	mov  x0, x22
	adr_l x1, k_internal_scope
	mov  x2, #14
	bl   find_raw
	mov  x1, x0
	bl   w_raw
	adr_l x0, k_expr_path
	bl   w_cstr
	mov  x0, x22
	adr_l x1, k_expr_path
	mov  x2, #15
	bl   find_raw
	mov  x1, x0
	bl   w_raw
	adr_l x9, b_hdlr_data
	sub  x3, x24, x9
	adr_l x9, g_tmplen
	str  x3, [x9]
	adr_l x0, t_handler
	mov  x1, #14
	adr_l x2, b_hdlr_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, hdlr_ch
	bl   mk_entity
	mov  x3, x0                      // blob len
	adr_l x9, g_hpat_ptr
	ldr  x0, [x9]                    // path ptr
	adr_l x9, g_hpat_len
	ldr  x1, [x9]                    // path len
	adr_l x2, b_ent_scratch          // blob ptr
	bl   reg_store

	// ===== 3. capability token {grants, grantee, granter, created_at} =====
	bl   now_ms
	adr_l x9, g_created
	str  x0, [x9]
	adr_l x24, b_htok_data
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_grants
	bl   w_cstr
	mov  x0, x21
	adr_l x1, k_req_scope
	mov  x2, #15
	bl   find_raw
	mov  x1, x0
	bl   w_raw
	adr_l x0, ka_grantee
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_granter
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_created
	bl   w_cstr
	adr_l x9, g_created
	ldr  x1, [x9]
	bl   w_uint
	adr_l x9, b_htok_data
	sub  x3, x24, x9
	adr_l x9, g_htoklen
	str  x3, [x9]
	adr_l x0, ta_token
	mov  x1, #23
	adr_l x2, b_htok_data
	adr_l x9, g_htoklen
	ldr  x3, [x9]
	adr_l x4, htok_ch
	bl   mk_entity
	// token store path = "system/capability/grants/" + pattern
	mov  x23, x0                     // entlen (survives pcat)
	adr_l x0, p_cap_grants
	mov  x1, #25
	adr_l x9, g_hpat_ptr
	ldr  x2, [x9]
	adr_l x9, g_hpat_len
	ldr  x3, [x9]
	bl   pcat                        // x0=b_hpath, x2=len
	mov  x1, x2                      // path len
	// x0 already = b_hpath (path ptr)
	adr_l x2, b_ent_scratch          // blob ptr
	mov  x3, x23                     // blob len
	bl   reg_store

	// ===== 4. signature {signer, target, algorithm, signature} over the token hash =====
	adr_l x0, g_seed
	adr_l x1, htok_ch
	mov  x2, #33
	adr_l x3, htok_sig
	bl   ec_ed25519_sign
	adr_l x24, b_hsig_data
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_signer
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_target
	bl   w_cstr
	adr_l x1, htok_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_algo
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_sig
	bl   w_cstr
	adr_l x1, htok_sig
	mov  x2, #64
	bl   w_bstr
	adr_l x9, b_hsig_data
	sub  x3, x24, x9
	adr_l x9, g_tmplen
	str  x3, [x9]
	adr_l x0, ta_sig
	mov  x1, #16
	adr_l x2, b_hsig_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, hsig_ch
	bl   mk_entity
	// sig store path = "system/signature/" + hex(htok_ch)
	mov  x23, x0                     // entlen
	adr_l x0, htok_ch
	adr_l x1, b_hex
	bl   hexenc
	adr_l x0, p_sig_slash
	mov  x1, #17
	adr_l x2, b_hex
	mov  x3, #66
	bl   pcat
	mov  x1, x2                      // path len
	// x0 already = b_hpath (path ptr)
	adr_l x2, b_ent_scratch          // blob ptr
	mov  x3, x23                     // blob len
	bl   reg_store

	// ===== register-result {grant:<token data>, pattern} =====
	adr_l x24, b_regres_data
	mov  x1, #2
	bl   w_map
	adr_l x0, k_grant
	bl   w_cstr
	adr_l x1, b_htok_data
	adr_l x9, g_htoklen
	ldr  x2, [x9]
	bl   w_raw
	adr_l x0, k_pattern
	bl   w_cstr
	adr_l x9, g_hpat_ptr
	ldr  x1, [x9]
	adr_l x9, g_hpat_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_regres_data
	sub  x3, x24, x9
	adr_l x9, g_tmplen
	str  x3, [x9]
	adr_l x0, t_reg_result
	mov  x1, #30
	adr_l x2, b_regres_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, regres_ch
	bl   mk_entity                   // entity → b_ent_scratch
	// wrap as the response result via send_get_ok
	mov  x1, x0                      // entlen
	adr_l x0, b_ent_scratch
	bl   send_get_ok
	b    .Lsr_done
.Lsr_400:
	mov  x0, #400
	adr_l x1, ec_unexpected_params
	bl   send_error
.Lsr_done:
	ldr  x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// serve_unregister(x0 = exec data map) — remove the handler entities for the pattern named by
// resource.targets[0] (= system/handler/<pattern>). Deletes interface, handler, token and the
// invariant-path signature, then returns 200 with a null result entity.
// x20=exec, x21=target ptr, x22=target len, x23=pattern ptr, x19=pattern len; cursor x24.
	.type serve_unregister, %function
serve_unregister:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]
	mov  x20, x0                     // exec
	mov  x0, x20
	bl   verify_get_auth
	cbnz x0, .Lsu_done
	mov  x0, x20
	bl   verify_get_cap
	cbnz x0, .Lsu_done
	mov  x0, x20
	bl   verify_get_scope
	cbnz x0, .Lsu_done
	// target = resource.targets[0]  (= system/handler/<pattern>)
	mov  x0, x20
	adr_l x1, k_resource
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lsu_ok
	adr_l x1, k_targets
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lsu_ok
	bl   read_head
	cbz  x2, .Lsu_ok
	bl   get_text                    // x0=target ptr, x2=target len (= interface path)
	mov  x21, x0                     // target ptr
	mov  x22, x2                     // target len
	// pattern = target after the "system/handler/" (15-byte) prefix
	add  x23, x21, #15               // pattern ptr
	sub  x19, x22, #15               // pattern len
	// token path = "system/capability/grants/" + pattern → look it up for its content_hash
	adr_l x0, p_cap_grants
	mov  x1, #25
	mov  x2, x23
	mov  x3, x19
	bl   pcat                        // x0=b_hpath, x2=len
	mov  x1, x0                      // path ptr (canon_path wants rsi→x1)
	mov  x3, x2                      // path len (canon_path wants rcx→x3)
	bl   canon_path                  // x0=canon, x2=len
	mov  x1, x0                      // path ptr (store_get wants rsi→x1)
	mov  x3, x2                      // path len (store_get wants rcx→x3)
	bl   store_get                   // x0=token blob|0
	cbz  x0, .Lsu_delrest
	// recompute sig path from the token's content_hash field → delete it
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lsu_delrest
	bl   get_text                    // x0 = 33-byte token hash ptr
	adr_l x1, b_hex
	bl   hexenc
	adr_l x0, p_sig_slash
	mov  x1, #17
	adr_l x2, b_hex
	mov  x3, #66
	bl   pcat
	mov  x1, x2                      // path len (store_delete wants rsi→x1)
	// x0 already = b_hpath (path ptr)
	bl   store_delete
.Lsu_delrest:
	// delete interface (= target), handler (= pattern), token (= grants path)
	mov  x0, x21
	mov  x1, x22
	bl   store_delete
	mov  x0, x23
	mov  x1, x19
	bl   store_delete
	adr_l x0, p_cap_grants
	mov  x1, #25
	mov  x2, x23
	mov  x3, x19
	bl   pcat
	mov  x1, x2                      // path len
	// x0 already = b_hpath (path ptr)
	bl   store_delete
.Lsu_ok:
	// 200 with a null result entity {data:null, type:"", content_hash:<33 zero>}
	adr_l x24, b_regres_env
	mov  x1, #3
	bl   w_map
	adr_l x0, k_data
	bl   w_cstr
	mov  w9, #0xf6                   // null
	strb w9, [x24]
	add  x24, x24, #1
	adr_l x0, k_type
	bl   w_cstr
	mov  w9, #0x60                   // empty text ""
	strb w9, [x24]
	add  x24, x24, #1
	adr_l x0, k_chash
	bl   w_cstr
	adr_l x1, b_zero33
	mov  x2, #33
	bl   w_bstr
	adr_l x9, b_regres_env
	sub  x1, x24, x9                 // entity len
	adr_l x0, b_regres_env
	bl   send_get_ok
.Lsu_done:
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret
	.type serve_configure, %function
serve_configure:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x19, x0                     // exec (was r12)
	mov  x0, x19
	bl   verify_get_auth
	cbnz x0, .Lsc_done
	mov  x0, x19
	bl   verify_get_cap
	cbnz x0, .Lsc_done
	// NB: no verify_get_scope — a configure request carries no resource.targets (the peer
	// policy names its scope via params.data.grants), so the target-based scope gate does not
	// apply; auth + capability presence is the gate.
	// params entity (raw span) → x20 ptr, x21 len (echoed + stored).
	mov  x0, x19
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsc_400
	mov  x20, x0                     // params entity start
	bl   skip_value
	sub  x21, x0, x20                // params entity len
	// peer_pattern = params.data.peer_pattern
	mov  x0, x20
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lsc_400
	adr_l x1, k_peer_pattern
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lsc_store              // no peer_pattern → nothing to validate/index
	bl   get_text                    // x0=pat ptr, x2=pat len
	mov  x22, x0                     // pattern ptr (was r15)
	mov  x23, x2                     // pattern len (was rbx)
	// §V7 §4 reject a partial-prefix wildcard peer_pattern (any '*') → 400 invalid_params.
	mov  x9, #0
.Lsc_wc:
	cmp  x9, x23
	b.hs .Lsc_wc_ok
	ldrb w10, [x22, x9]             // '*'
	cmp  w10, #0x2a
	b.eq .Lsc_invalid
	add  x9, x9, #1
	b    .Lsc_wc
.Lsc_wc_ok:
	// store the policy-entry at system/capability/policy/<peer_pattern>
	adr_l x0, p_cap_policy
	mov  x1, #25
	mov  x2, x22
	mov  x3, x23
	bl   pcat                        // x0=b_hpath, x2=len
	mov  x1, x2                      // len
	// x0 already = path ptr
	mov  x2, x20                     // params entity ptr
	mov  x3, x21                     // params entity len
	bl   reg_store
.Lsc_store:
	// echo the params policy-entry entity verbatim as the 200 result
	mov  x0, x20
	mov  x1, x21
	bl   send_get_ok
	b    .Lsc_done
.Lsc_invalid:
	mov  x0, #400
	adr_l x1, ec_invalid_params
	bl   send_error
	b    .Lsc_done
.Lsc_400:
	mov  x0, #400
	adr_l x1, ec_unexpected_params
	bl   send_error
.Lsc_done:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// serve_delegate(x0 = exec) — §6.9a delegate. v1 is same-peer-only; a request with a parent
// field is unsupported (501, construct the attenuated child client-side); one lacking the
// required parent field is malformed (400 invalid_params).
	.type serve_delegate, %function
serve_delegate:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	// x0 = exec (no callee-saved needed — value not held across a call)
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsdl2_501
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lsdl2_501
	adr_l x1, ka_parent
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsdl2_noparent
.Lsdl2_501:
	mov  x0, #501
	adr_l x1, ec_unsupported_op
	bl   send_error
	b    .Lsdl2_done
.Lsdl2_noparent:
	mov  x0, #400
	adr_l x1, ec_invalid_params
	bl   send_error
.Lsdl2_done:
	ldp  x29, x30, [sp], #16
	ret

// serve_revoke(x0 = exec) — §6.9a revoke. Writes a system/capability/revocation marker at
// system/capability/revocations/<hex(token)> and returns 200 with the revocation entity. A
// zero token is rejected (400 invalid_params).
	.type serve_revoke, %function
serve_revoke:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]         // save x24 (global cursor) — this fn sets it up
	mov  x19, x0                     // exec (was r12)
	mov  x0, x19
	bl   verify_get_auth
	cbnz x0, .Lrv_done
	mov  x0, x19
	bl   verify_get_cap
	cbnz x0, .Lrv_done
	mov  x0, x19
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lrv_400
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lrv_400
	mov  x20, x0                     // params.data (was r13)
	// token (33B) → x21 (was r14)
	adr_l x1, ka_token
	mov  x2, #5
	bl   map_find
	cbz  x0, .Lrv_400
	bl   get_text                    // x0=token ptr, x2=len
	cmp  x2, #33
	b.ne .Lrv_400
	mov  x21, x0                     // token ptr
	// reject an all-zero token
	mov  x9, #0                      // index
	mov  x10, #0                     // OR accumulator
.Lrv_zscan:
	cmp  x9, #33
	b.hs .Lrv_zdone
	ldrb w11, [x21, x9]
	orr  w10, w10, w11
	add  x9, x9, #1
	b    .Lrv_zscan
.Lrv_zdone:
	cbz  x10, .Lrv_invalid           // all-zero token
	bl   now_ms
	adr_l x9, g_created
	str  x0, [x9]
	// reason (verbatim) if present
	mov  x0, x20
	adr_l x1, k_reason
	mov  x2, #6
	bl   find_raw                    // x0=value ptr|0, x2=value len
	mov  x22, x0                     // reason value ptr (0 if absent) (was rbx)
	adr_l x9, g_tmplen
	str  x2, [x9]                    // reason len
	// ---- revocation data ----
	adr_l x23, b_revoke_data         // cursor tracker (was r15); x24 = write cursor
	mov  x24, x23
	cbz  x22, .Lrv_map2
	mov  x1, #3
	bl   w_map
	b    .Lrv_tok
.Lrv_map2:
	mov  x1, #2
	bl   w_map
.Lrv_tok:
	adr_l x0, ka_token
	bl   w_cstr
	mov  x1, x21                     // token ptr
	mov  x2, #33
	bl   w_bstr
	cbz  x22, .Lrv_revat
	adr_l x0, k_reason
	bl   w_cstr
	mov  x1, x22                     // reason ptr
	adr_l x9, g_tmplen
	ldr  x2, [x9]                    // reason len
	bl   w_raw
.Lrv_revat:
	adr_l x0, k_revoked_at
	bl   w_cstr
	adr_l x9, g_created
	ldr  x1, [x9]
	bl   w_uint
	adr_l x9, b_revoke_data
	sub  x9, x24, x9                 // data len
	adr_l x10, g_tmplen
	str  x9, [x10]
	adr_l x0, t_revocation
	mov  x1, #28
	adr_l x2, b_revoke_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, revoke_ch
	bl   mk_entity                   // x0=entlen; entity in b_ent_scratch
	mov  x23, x0                     // entlen (was r15)
	// store at system/capability/revocations/<hex(token)>
	mov  x0, x21                     // token ptr
	adr_l x1, b_hex
	bl   hexenc
	adr_l x0, p_cap_revoke
	mov  x1, #30
	adr_l x2, b_hex
	mov  x3, #66
	bl   pcat                        // x0=path ptr, x2=len
	mov  x1, x2                      // len
	adr_l x2, b_ent_scratch
	mov  x3, x23                     // entlen
	bl   reg_store
	// 200 result = the revocation entity
	adr_l x0, b_ent_scratch
	mov  x1, x23                     // entlen
	bl   send_get_ok
	b    .Lrv_done
.Lrv_invalid:
	mov  x0, #400
	adr_l x1, ec_invalid_params
	bl   send_error
	b    .Lrv_done
.Lrv_400:
	mov  x0, #400
	adr_l x1, ec_unexpected_params
	bl   send_error
.Lrv_done:
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// is_revoked(x0 = 33-byte token hash) -> x0 = 1 if a revocation marker exists in the store.
	.type is_revoked, %function
is_revoked:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	// x0 = token ptr (not held across a call after hexenc consumes it)
	adr_l x1, b_hex
	bl   hexenc
	adr_l x0, p_cap_revoke
	mov  x1, #30
	adr_l x2, b_hex
	mov  x3, #66
	bl   pcat                        // x0=b_hpath, x2=len
	mov  x1, x0                      // path ptr → rsi
	mov  x3, x2                      // path len → x3 (canon_path wants rcx→x3)
	bl   canon_path                  // x0=canon, x2=len
	mov  x1, x0                      // canon → rsi
	mov  x3, x2                      // canon len → x3 (store_get wants rcx→x3)
	bl   store_get                   // x0=blob|0
	cmp  x0, #0
	cset x0, ne                      // setnz + movzbl → 0/1
	ldp  x29, x30, [sp], #16
	ret

// seed_one(x0=pattern ptr, x1=pattern len, x2=interface ptr, x3=interface len) — publish a
// §6.2 native dispatch entity  {interface:<interface>}  (type system/handler, no expression_path
// ⇒ dispatch_type native) at the bare pattern path.
	.type seed_one, %function
seed_one:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]         // save x24 (global cursor)
	mov  x19, x0                     // pattern ptr (was r12)
	mov  x20, x1                     // pattern len (was r13)
	mov  x21, x2                     // interface ptr (was rbx)
	mov  x22, x3                     // interface len (was r14)
	adr_l x23, b_hdlr_data           // cursor tracker (was r15)
	mov  x24, x23
	mov  x1, #1
	bl   w_map
	adr_l x0, k_interface
	bl   w_cstr
	mov  x1, x21                     // interface ptr
	mov  x2, x22                     // interface len
	bl   w_txt
	adr_l x9, b_hdlr_data
	sub  x9, x24, x9
	adr_l x10, g_tmplen
	str  x9, [x10]
	adr_l x0, t_handler
	mov  x1, #14
	adr_l x2, b_hdlr_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, hdlr_ch
	bl   mk_entity                   // x0 = entlen
	mov  x3, x0                      // entlen → rcx (reg_store arg 4)
	mov  x0, x19                     // pattern ptr
	mov  x1, x20                     // pattern len
	adr_l x2, b_ent_scratch
	bl   reg_store
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// seed_dispatch_entities — publish the built-in native dispatch entities (§6.2 N2/N5) into the
// per-fork store so a get at system/{tree,protocol/connect,capability} resolves a system/handler
// entity with an `interface` ref. Called once per connection (per fork).
	.type seed_dispatch_entities, %function
seed_dispatch_entities:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	adr_l x0, va_systree
	mov  x1, #11
	adr_l x2, s_iface_tree
	mov  x3, #26
	bl   seed_one
	adr_l x0, s_pat_connect
	mov  x1, #23
	adr_l x2, s_iface_connect
	mov  x3, #38
	bl   seed_one
	adr_l x0, va_syscap
	mov  x1, #17
	adr_l x2, s_iface_cap
	mov  x3, #32
	bl   seed_one
	// §7a validate scaffold — publishing system/handler/system/validate/dispatch-outbound is
	// the oracle's --validate gate for BOTH validate_echo_dispatch and t1_2_concurrent_reentry.
	adr_l x0, s_name_echo
	adr_l x1, s_pat_echo
	adr_l x2, va_echo
	adr_l x3, s_iface_echo
	bl   seed_vh
	adr_l x0, s_name_dout
	adr_l x1, s_pat_dout
	adr_l x2, va_dispatch
	adr_l x3, s_iface_dout
	bl   seed_vh
	ldp  x29, x30, [sp], #16
	ret

// seed_vh(x0=name cstr, x1=pattern cstr, x2=op cstr, x3=interface cstr) — publish a
// validate handler: interface {name,pattern,operations:{op:{input_type,output_type}}} at the
// interface path + a native dispatch entity at the pattern path. Lengths via strlen.
	.type seed_vh, %function
seed_vh:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]         // save x24 (global cursor)
	mov  x19, x0                     // name (was r12)
	mov  x20, x1                     // pattern (was r13)
	mov  x21, x2                     // op (was rbx)
	mov  x22, x3                     // interface (was r14)
	adr_l x23, b_iface_data          // cursor tracker (was r15)
	mov  x24, x23
	mov  x1, #3
	bl   w_map
	adr_l x0, k_name
	bl   w_cstr
	mov  x0, x19                     // name
	bl   w_cstr
	adr_l x0, k_pattern
	bl   w_cstr
	mov  x0, x20                     // pattern
	bl   w_cstr
	adr_l x0, ka_operations
	bl   w_cstr
	mov  x1, #1
	bl   w_map
	mov  x0, x21                     // op key
	bl   w_cstr
	mov  x1, #2
	bl   w_map
	adr_l x0, k_input_type
	bl   w_cstr
	adr_l x0, v_prim_any
	bl   w_cstr
	adr_l x0, k_output_type
	bl   w_cstr
	adr_l x0, v_prim_any
	bl   w_cstr
	adr_l x9, b_iface_data
	sub  x9, x24, x9
	adr_l x10, g_tmplen
	str  x9, [x10]
	adr_l x0, t_iface
	mov  x1, #24
	adr_l x2, b_iface_data
	adr_l x9, g_tmplen
	ldr  x3, [x9]
	adr_l x4, iface_ch
	bl   mk_entity
	mov  x23, x0                     // entlen (was r15)
	mov  x0, x22                     // interface
	bl   strlen                      // x0 = interface len
	mov  x1, x0                      // interface len → rsi
	mov  x0, x22                     // interface ptr → rdi
	adr_l x2, b_ent_scratch
	mov  x3, x23                     // entlen
	bl   reg_store
	// native dispatch entity at the pattern path
	mov  x0, x20                     // pattern
	bl   strlen                      // x0 = pattern len
	mov  x19, x0                     // pattern len (was r12; name no longer needed)
	mov  x0, x22                     // interface
	bl   strlen                      // x0 = interface len
	mov  x3, x0                      // ifacelen (seed_one arg 4)
	mov  x0, x20                     // pattern ptr
	mov  x1, x19                     // pattern len
	mov  x2, x22                     // interface ptr
	bl   seed_one
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// gen_erid — build a unique outbound-echo request_id "e<hex>" into b_erid (len → g_erid_len).
	.type gen_erid, %function
gen_erid:
	adr_l x9, echo_ctr
	ldr  x0, [x9]
	adr_l x1, b_erid
	mov  w9, #0x65                   // 'e'
	strb w9, [x1]
	lsr  x2, x0, #4
	and  x2, x2, #0xf
	adr_l x3, hexchars
	ldrb w2, [x3, x2]
	strb w2, [x1, #1]
	and  x2, x0, #0xf
	adr_l x3, hexchars
	ldrb w2, [x3, x2]
	strb w2, [x1, #2]
	adr_l x9, g_erid_len
	mov  x10, #3
	str  x10, [x9]
	adr_l x9, echo_ctr
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	ret

// fill_incl(x0=incl entry ptr, x1=parent map, x2=key cstr, x3=key len, x4=type cstr) —
// populate a 40-byte emit_sorted_included entry from a parent[key] sub-entity:
// [0]=chash(key) [8]=type [16]=data ptr [24]=data len [32]=chash.
	.type fill_incl, %function
fill_incl:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x0                     // entry (was r12)
	mov  x21, x4                     // type cstr (was r14)
	mov  x0, x1                      // parent → rdi
	mov  x1, x2                      // key → rsi
	mov  x2, x3                      // keylen → rdx
	bl   map_find                    // x0 = entity map
	cbz  x0, .Lfi_ret
	mov  x20, x0                     // entity (was r13)
	// content_hash
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lfi_ret
	bl   get_text                    // x0 = chash ptr
	str  x0, [x19]                   // [0]
	str  x0, [x19, #32]             // [32]
	str  x21, [x19, #8]            // [8] type
	// data span
	mov  x0, x20                     // entity
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lfi_ret
	str  x0, [x19, #16]            // [16] data ptr
	bl   skip_value
	ldr  x9, [x19, #16]
	sub  x0, x0, x9                 // data len
	str  x0, [x19, #24]           // [24]
.Lfi_ret:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// serve_dispatch_outbound(x0 = exec) — §7a.2a: originate a reentry echo EXECUTE to the target
// peer (the validator, same socket) using the handed-in reentry_capability, and record the
// pending dispatch so its response is emitted when the echo reply arrives (handle_dispatch_response).
	.type serve_dispatch_outbound, %function
serve_dispatch_outbound:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]         // save x24 (global cursor)
	mov  x19, x0                     // exec (was r12)
	// pd = exec.params.data → x20 (was r13)
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsdo_ret
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lsdo_ret
	mov  x20, x0                     // pd
	// target text
	adr_l x1, k_target
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lsdo_ret
	bl   get_text                    // x0=ptr, x2=len
	adr_l x9, g_dtarget_ptr
	str  x0, [x9]
	adr_l x9, g_dtarget_len
	str  x2, [x9]
	// rcap_hash = reentry_capability.content_hash
	mov  x0, x20
	adr_l x1, k_reentry_capability
	mov  x2, #18
	bl   map_find
	cbz  x0, .Lsdo_ret
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lsdo_ret
	bl   get_text
	adr_l x9, g_rcap_hash
	str  x0, [x9]
	// ---- echo params entity {data:<value map>, type:primitive/any, content_hash} ----
	mov  x0, x20
	adr_l x1, k_value
	mov  x2, #5
	bl   find_raw                    // x0=value map ptr, x2=len
	adr_l x9, g_dvalue_ptr
	str  x0, [x9]
	adr_l x9, g_dvalue_len
	str  x2, [x9]
	adr_l x0, t_prim_any
	mov  x1, #13
	adr_l x9, g_dvalue_ptr
	ldr  x2, [x9]
	adr_l x9, g_dvalue_len
	ldr  x3, [x9]
	adr_l x4, eparams_ch
	bl   ec_content_hash
	adr_l x23, b_eparams             // cursor tracker (was r15)
	mov  x24, x23
	adr_l x0, t_prim_any
	adr_l x9, g_dvalue_ptr
	ldr  x1, [x9]
	adr_l x9, g_dvalue_len
	ldr  x2, [x9]
	adr_l x3, eparams_ch
	bl   w_entity                    // echo params entity → b_eparams
	adr_l x9, b_eparams
	sub  x2, x24, x9
	adr_l x9, g_eplen
	str  x2, [x9]                    // echo params entity len
	// ---- EXECUTE data {uri, author, params, operation, capability, request_id} ----
	bl   gen_erid
	adr_l x23, b_edata               // cursor tracker (was r15)
	mov  x24, x23
	mov  x1, #6
	bl   w_map
	adr_l x0, k_uri
	bl   w_cstr
	adr_l x9, g_dtarget_ptr
	ldr  x1, [x9]
	adr_l x9, g_dtarget_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x0, k_author
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_params
	bl   w_cstr
	adr_l x1, b_eparams
	adr_l x9, g_eplen
	ldr  x2, [x9]
	bl   w_raw
	adr_l x0, k_op
	bl   w_cstr
	adr_l x0, va_echo
	bl   w_cstr
	adr_l x0, k_capability
	bl   w_cstr
	adr_l x9, g_rcap_hash
	ldr  x1, [x9]
	mov  x2, #33
	bl   w_bstr
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x1, b_erid
	adr_l x9, g_erid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_edata
	sub  x2, x24, x9
	adr_l x9, g_edlen
	str  x2, [x9]
	// ch(execute data)
	adr_l x0, t_execute
	mov  x1, #23
	adr_l x2, b_edata
	adr_l x9, g_edlen
	ldr  x3, [x9]
	adr_l x4, edata_ch
	bl   ec_content_hash
	// ---- our PoP signature over the EXECUTE hash ----
	adr_l x0, g_seed
	adr_l x1, edata_ch
	mov  x2, #33
	adr_l x3, esig_bytes
	bl   ec_ed25519_sign
	adr_l x23, b_esig                // cursor tracker (was r15)
	mov  x24, x23
	mov  x1, #4
	bl   w_map
	adr_l x0, ka_signer
	bl   w_cstr
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_target
	bl   w_cstr
	adr_l x1, edata_ch
	mov  x2, #33
	bl   w_bstr
	adr_l x0, ka_algo
	bl   w_cstr
	adr_l x0, v_ed25519
	bl   w_cstr
	adr_l x0, ka_sig
	bl   w_cstr
	adr_l x1, esig_bytes
	mov  x2, #64
	bl   w_bstr
	adr_l x9, b_esig
	sub  x22, x24, x9                // esig data len (was r14)
	adr_l x0, ta_sig
	mov  x1, #16
	adr_l x2, b_esig
	mov  x3, x22
	adr_l x4, esig_ch
	bl   ec_content_hash
	// ---- included table: 5 entries ----
	adr_l x21, do_incl_tab           // table base (was rbx)
	// entry 0: our peer
	adr_l x9, g_identity_hash
	str  x9, [x21]
	adr_l x9, ta_peer
	str  x9, [x21, #8]
	adr_l x9, b_peerdata
	str  x9, [x21, #16]
	adr_l x9, g_peerdata_len
	ldr  x9, [x9]
	str  x9, [x21, #24]
	adr_l x9, g_identity_hash
	str  x9, [x21, #32]
	// entry 1: our PoP signature
	adr_l x9, esig_ch
	str  x9, [x21, #40]
	adr_l x9, ta_sig
	str  x9, [x21, #48]
	adr_l x9, b_esig
	str  x9, [x21, #56]
	str  x22, [x21, #64]
	adr_l x9, esig_ch
	str  x9, [x21, #72]
	// entry 2: reentry_capability
	add  x0, x21, #80
	mov  x1, x20
	adr_l x2, k_reentry_capability
	mov  x3, #18
	adr_l x4, ta_token
	bl   fill_incl
	// entry 3: reentry_granter (granter peer)
	add  x0, x21, #120
	mov  x1, x20
	adr_l x2, k_reentry_granter
	mov  x3, #15
	adr_l x4, ta_peer
	bl   fill_incl
	// entry 4: reentry_cap_signature
	add  x0, x21, #160
	mov  x1, x20
	adr_l x2, k_reentry_cap_signature
	mov  x3, #21
	adr_l x4, ta_sig
	bl   fill_incl
	// ---- envelope {root:<EXECUTE entity>, included} ----
	adr_l x23, b_do_env              // cursor tracker (was r15)
	mov  x24, x23
	mov  x1, #2
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_execute
	adr_l x1, b_edata
	adr_l x9, g_edlen
	ldr  x2, [x9]
	adr_l x3, edata_ch
	bl   w_entity
	adr_l x0, ka_included
	bl   w_cstr
	mov  w0, #5
	adr_l x1, do_incl_tab
	bl   emit_sorted_included
	// ---- frame + send to the validator (as B) on this connection ----
	adr_l x9, b_do_env
	sub  x22, x24, x9                // envelope len (was r14)
	rev  w9, w22
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_do_env
	mov  x2, x22
	bl   write_all
	// ---- record pending {echo_rid → dispatch request_id} ----
	adr_l x9, pending_n
	ldr  x0, [x9]
	cmp  x0, #16
	b.hs .Lsdo_ret                   // table full — drop
	mov  x9, #80
	mul  x9, x0, x9
	adr_l x21, pending_tab           // table base (was rbx)
	add  x21, x21, x9                // entry
	// copy echo_rid
	mov  x0, x21                     // dst
	adr_l x1, b_erid                 // src
	adr_l x9, g_erid_len
	ldr  x2, [x9]
	bl   mcpy
	adr_l x9, g_erid_len
	ldr  x9, [x9]
	str  x9, [x21, #32]
	// copy dispatch request_id (g_rid)
	add  x0, x21, #40                // dst
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]                    // src
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   mcpy
	adr_l x9, g_rid_len
	ldr  x9, [x9]
	str  x9, [x21, #72]
	adr_l x9, pending_n
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
.Lsdo_ret:
	ldp  x23, x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// handle_dispatch_response(x0 = response root.data map = {result, status, request_id}) —
// match the echo reply's request_id to a pending dispatch-outbound and emit its 200 response
// {result:{type:primitive/any, data:{result:<echo result>, status:<echo status>}}, status:200}.
	.type handle_dispatch_response, %function
handle_dispatch_response:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	str  x24, [sp, #64]             // save x24 (global cursor)
	mov  x19, x0                     // response data (was r12)
	// request_id → find pending entry
	adr_l x1, k_rid
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lhdr_ret
	bl   get_text                    // x0=erid ptr, x2=erid len
	mov  x20, x0                     // erid ptr (was r13)
	mov  x21, x2                     // erid len (was r14)
	adr_l x22, pending_tab           // table base (was rbx)
	adr_l x9, pending_n
	ldr  x23, [x9]                   // pending_n (was r15)
	mov  x25, #0                     // scan index (was r10)
.Lhdr_scan:
	cmp  x25, x23
	b.hs .Lhdr_ret                   // no match (unknown response)
	mov  x9, #80
	mul  x9, x25, x9
	adr_l x22, pending_tab
	add  x22, x22, x9                // entry
	ldr  x9, [x22, #32]             // entry.erid_len
	cmp  x9, x21
	b.ne .Lhdr_next
	mov  x0, x22
	mov  x1, x20
	mov  x2, x21                     // len → rcx (memeq x2)
	bl   memeq
	cbnz x0, .Lhdr_found
.Lhdr_next:
	add  x25, x25, #1
	b    .Lhdr_scan
.Lhdr_found:
	// save the dispatch request_id (entry+40, len entry+72) into g_rid so send helpers echo it
	add  x9, x22, #40
	adr_l x10, g_rid_ptr
	str  x9, [x10]
	ldr  x9, [x22, #72]
	adr_l x10, g_rid_len
	str  x9, [x10]
	// echo result entity (raw span) = response.result
	mov  x0, x19
	adr_l x1, k_result
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lhdr_ret
	mov  x20, x0                     // echo result entity ptr (was r13)
	bl   skip_value
	sub  x21, x0, x20                // echo result len (was r14)
	// ---- inner {result:<echo result>, status:200} ----
	adr_l x25, b_do_inner            // cursor tracker (was r15)
	mov  x24, x25
	mov  x1, #2
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	mov  x1, x20                     // echo result ptr
	mov  x2, x21                     // echo result len
	bl   w_raw
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x9, b_do_inner
	sub  x21, x24, x9                // inner len (was r14)
	adr_l x0, t_prim_any
	mov  x1, #13
	adr_l x2, b_do_inner
	mov  x3, x21
	adr_l x4, do_inner_ch
	bl   ec_content_hash
	// ---- response data {result:<outer result entity>, status:200, request_id} ----
	adr_l x25, b_do_data             // cursor tracker (was r15)
	mov  x24, x25
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	adr_l x0, t_prim_any
	adr_l x1, b_do_inner
	mov  x2, x21                     // inner len
	adr_l x3, do_inner_ch
	bl   w_entity
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x9, b_do_data
	sub  x21, x24, x9                // response data len (was r14)
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_do_data
	mov  x3, x21
	adr_l x4, do_data_ch
	bl   ec_content_hash
	// ---- envelope {root:<response entity>} ----
	adr_l x25, b_do_env              // cursor tracker (was r15)
	mov  x24, x25
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_do_data
	mov  x2, x21                     // response data len
	adr_l x3, do_data_ch
	bl   w_entity
	adr_l x9, b_do_env
	sub  x21, x24, x9                // envelope len (was r14)
	rev  w9, w21
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_do_env
	mov  x2, x21
	bl   write_all
.Lhdr_ret:
	ldr  x24, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret
	.type store_delete, %function
store_delete:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x3, x1                      // len -> x3 (canon_path: x1=ptr, x3=len)
	mov  x1, x0                      // ptr -> x1
	bl   canon_path                  // x0=canon, x2=len
	mov  x22, x0                     // canon (r13)
	mov  x23, x2                     // len (r14)
	adr_l x19, store_idx             // rbx
	adr_l x9, store_count
	ldr  x21, [x9]                   // r12 = store_count
.Lsdl_scan:
	cbz  x21, .Lsdl_ret
	ldr  x9, [x19, #8]              // entry Klen
	cmp  x9, x23
	b.ne .Lsdl_next
	ldr  x0, [x19]                  // entry key ptr
	mov  x1, x22
	mov  x2, x23
	bl   memeq
	cbnz x0, .Lsdl_found
.Lsdl_next:
	add  x19, x19, #32
	sub  x21, x21, #1
	b    .Lsdl_scan
.Lsdl_found:
	adr_l x9, store_count
	ldr  x10, [x9]
	sub  x10, x10, #1
	lsl  x10, x10, #5
	adr_l x11, store_idx
	add  x11, x11, x10               // x11 = last entry
	ldr  x9, [x11]
	str  x9, [x19]
	ldr  x9, [x11, #8]
	str  x9, [x19, #8]
	ldr  x9, [x11, #16]
	str  x9, [x19, #16]
	ldr  x9, [x11, #24]
	str  x9, [x19, #24]
	adr_l x9, store_count
	ldr  x10, [x9]
	sub  x10, x10, #1
	str  x10, [x9]
.Lsdl_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// serve_tree_listing(x0 = raw prefix ptr, x1 = raw prefix len) — a trailing-slash tree get.
// Scans the per-fork store for canonical keys under /{localPeerID}/{prefix} (or under an
// absolute prefix verbatim), groups by immediate child segment, and emits a 200
// system/tree/listing {path, count, offset, entries:{seg→{hash, has_children}}}. Empty →
// falls back to the read-only typestore listing (system/type/) else a 200 empty listing.
	.type serve_tree_listing, %function
serve_tree_listing:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	adr_l x9, g_lprefix_ptr
	str  x0, [x9]
	adr_l x9, g_lprefix_len
	str  x1, [x9]
	mov  x3, x1                      // len -> x3 (canon_path wants rcx→x3)
	mov  x1, x0                      // ptr -> x1
	bl   canon_path                  // x0=cprefix ptr, x2=cprefix len
	adr_l x9, g_cpref_ptr
	str  x0, [x9]
	adr_l x9, g_cpref_len
	str  x2, [x9]
	adr_l x9, listing_n
	str  xzr, [x9]
	adr_l x19, store_idx             // rbx
	adr_l x9, store_count
	ldr  x20, [x9]                   // r12 = store_count
.Lstl_scan:
	cbz  x20, .Lstl_emit
	ldr  x21, [x19, #8]            // Klen (r13)
	adr_l x9, g_cpref_len
	ldr  x9, [x9]
	cmp  x21, x9
	b.lo .Lstl_next                  // key shorter than prefix
	ldr  x0, [x19]
	adr_l x9, g_cpref_ptr
	ldr  x1, [x9]
	adr_l x9, g_cpref_len
	ldr  x2, [x9]
	bl   memeq
	cbz  x0, .Lstl_next
	ldr  x22, [x19]                 // r14 = rest ptr base
	adr_l x9, g_cpref_len
	ldr  x9, [x9]
	add  x22, x22, x9                // rest ptr
	mov  x23, x21                    // r15 = restlen
	sub  x23, x23, x9                // restlen = Klen - cpref_len
	cbz  x23, .Lstl_next             // exact prefix (the node itself)
	mov  x9, #0                      // j = index of first '/'  (rcx)
.Lstl_slash:
	cmp  x9, x23
	b.hs .Lstl_slashdone
	ldrb w10, [x22, x9]
	cmp  w10, #0x2f
	b.eq .Lstl_slashdone
	add  x9, x9, #1
	b    .Lstl_slash
.Lstl_slashdone:
	mov  x0, x22                     // seg ptr
	mov  x1, x9                      // seg len (= j)
	mov  x4, #0                      // r8 = has_child
	cmp  x1, x23                     // j < restlen → has deeper segment
	b.hs .Lstl_add
	mov  x4, #1
.Lstl_add:
	ldr  x2, [x19, #16]            // blob ptr (leaf hash source)
	bl   add_listing_entry
.Lstl_next:
	add  x19, x19, #32
	sub  x20, x20, #1
	b    .Lstl_scan
.Lstl_emit:
	adr_l x9, listing_n
	ldr  x9, [x9]
	cbnz x9, .Lstl_build
	// no store children — fall back to the read-only typestore listing key, else 200 empty.
	adr_l x9, g_lprefix_ptr
	ldr  x1, [x9]
	adr_l x9, g_lprefix_len
	ldr  x2, [x9]
	bl   typestore_lookup
	cbz  x0, .Lstl_build             // nothing → emit an empty listing
	mov  x1, x2                      // (send_get_ok: x0=ptr, x1=len)
	bl   send_get_ok
	b    .Lstl_done
.Lstl_build:
	bl   emit_listing
.Lstl_done:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// add_listing_entry(x0=seg ptr, x1=seg len, x2=blob ptr, x4=has_child) — insert-or-merge a
// child segment into listing_ents. A segment seen as both leaf and parent becomes has_children
// with a null hash (matching the reference: intermediate nodes carry hash:null).
	.type add_listing_entry, %function
add_listing_entry:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x22, x0                     // seg ptr (r13)
	mov  x23, x1                     // seg len (r14)
	mov  x21, x2                     // blob ptr (r15)
	mov  x20, x4                     // has_child (r12)
	// §6.3 — a leaf bound to a system/deletion-marker is omitted from listings.
	cbnz x20, .Lale_notmarker
	mov  x0, x21
	adr_l x1, k_type
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lale_notmarker
	bl   get_text                    // x0=type ptr, x2=len
	cmp  x2, #22
	b.ne .Lale_notmarker
	adr_l x1, t_deletion_marker
	mov  x2, #22                     // memeq: x0=type ptr, x1=needle, x2=len
	bl   memeq
	cbnz x0, .Lale_ret               // deletion-marker leaf → skip
.Lale_notmarker:
	adr_l x19, listing_ents          // rbx
	adr_l x9, listing_n
	ldr  x25, [x9]                   // r10 (counter — callee-saved across memeq)
.Lale_scan:
	cbz  x25, .Lale_new
	ldr  x9, [x19, #8]
	cmp  x9, x23
	b.ne .Lale_scannext
	ldr  x0, [x19]
	mov  x1, x22
	mov  x2, x23
	bl   memeq
	cbnz x0, .Lale_found
.Lale_scannext:
	add  x19, x19, #32
	sub  x25, x25, #1
	b    .Lale_scan
.Lale_found:
	cbz  x20, .Lale_ret              // existing entry already covers this segment
	mov  x9, #1
	str  x9, [x19, #24]             // promote to parent
	str  xzr, [x19, #16]           // parent hash is null
	b    .Lale_ret
.Lale_new:
	adr_l x9, listing_n
	ldr  x0, [x9]
	cmp  x0, #384
	b.hs .Lale_ret                   // cap guard
	lsl  x0, x0, #5
	adr_l x19, listing_ents
	add  x19, x19, x0
	str  x22, [x19]
	str  x23, [x19, #8]
	cbnz x20, .Lale_parent
	// leaf: hash = blob's content_hash field
	mov  x0, x21
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lale_hashnull
	bl   get_text                    // x0 = chash ptr
	str  x0, [x19, #16]
	b    .Lale_setchild
.Lale_hashnull:
	str  xzr, [x19, #16]
	b    .Lale_setchild
.Lale_parent:
	str  xzr, [x19, #16]
.Lale_setchild:
	str  x20, [x19, #24]
	adr_l x9, listing_n
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
.Lale_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// sort_listing — bubble-sort listing_ents by (seg_len, then bytewise) for canonical map order.
	.type sort_listing, %function
sort_listing:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	adr_l x9, listing_n
	ldr  x21, [x9]                   // r12 = n
	cmp  x21, #2
	b.lo .Lsl_ret
.Lsl_outer:
	mov  x22, #0                     // i (r13)
	mov  x23, #0                     // swapped flag (r14)
	adr_l x19, listing_ents          // rbx
.Lsl_inner:
	sub  x9, x21, #1                 // n-1
	cmp  x22, x9
	b.hs .Lsl_outer_end
	// compare entry[i] (x19) vs entry[i+1] (x19+32)
	ldr  x0, [x19, #8]             // a.len
	ldr  x1, [x19, #40]            // b.len
	cmp  x0, x1
	b.hi .Lsl_swap                   // a longer → a after b
	b.lo .Lsl_noswap
	// equal length → bytewise compare a vs b
	ldr  x0, [x19]
	ldr  x1, [x19, #32]
	ldr  x2, [x19, #8]             // len -> x2 (mcmp_lex: x0=a, x1=b, x2=len)
	bl   mcmp_lex                    // w0 = -1/0/1
	cmp  w0, #0
	b.gt .Lsl_swap
	b    .Lsl_noswap
.Lsl_swap:
	// swap the two 32-byte entries (4 quads)
	ldr  x9, [x19]      ; ldr x10, [x19, #32] ; str x10, [x19]      ; str x9, [x19, #32]
	ldr  x9, [x19, #8]  ; ldr x10, [x19, #40] ; str x10, [x19, #8]  ; str x9, [x19, #40]
	ldr  x9, [x19, #16] ; ldr x10, [x19, #48] ; str x10, [x19, #16] ; str x9, [x19, #48]
	ldr  x9, [x19, #24] ; ldr x10, [x19, #56] ; str x10, [x19, #24] ; str x9, [x19, #56]
	mov  x23, #1
.Lsl_noswap:
	add  x19, x19, #32
	add  x22, x22, #1
	b    .Lsl_inner
.Lsl_outer_end:
	cbnz x23, .Lsl_outer
.Lsl_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// mcmp_lex(x0=a, x1=b, x2=len) -> w0 = -1 if a<b, 0 if equal, 1 if a>b (bytewise). Leaf.
	.type mcmp_lex, %function
mcmp_lex:
.Lmcl:
	cbz  x2, .Lmcl_eq
	ldrb w9, [x0]
	ldrb w10, [x1]
	cmp  w9, w10
	b.lo .Lmcl_lt
	b.hi .Lmcl_gt
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	b    .Lmcl
.Lmcl_eq:
	mov  w0, #0
	ret
.Lmcl_lt:
	mov  w0, #-1
	ret
.Lmcl_gt:
	mov  w0, #1
	ret

// w_map_hdr(x1 = count) — emit a CBOR map header (major 5) for an arbitrary count via x24.
	.type w_map_hdr, %function
w_map_hdr:
	cmp  x1, #24
	b.hs .Lwmh_1
	mov  w9, #0xa0
	orr  w9, w9, w1
	strb w9, [x24]
	add  x24, x24, #1
	ret
.Lwmh_1:
	cmp  x1, #256
	b.hs .Lwmh_2
	mov  w9, #0xb8
	strb w9, [x24]
	add  x24, x24, #1
	strb w1, [x24]
	add  x24, x24, #1
	ret
.Lwmh_2:
	mov  w9, #0xb9
	strb w9, [x24]
	add  x24, x24, #1
	rev16 w9, w1                     // 2-byte big-endian
	strh w9, [x24]
	add  x24, x24, #2
	ret

// emit_listing — sort listing_ents, build the system/tree/listing entity, send it (200) by
// reusing send_get_ok (which wraps a verbatim entity blob as the response result).
	.type emit_listing, %function
emit_listing:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	bl   sort_listing
	// ---- listing data {path, count, offset, entries} ----
	adr_l x24, b_list_data           // r15 = cursor
	mov  x1, #4                      // w_map: x1 = n
	bl   w_map
	adr_l x0, k_path
	bl   w_cstr
	adr_l x9, g_lprefix_ptr
	ldr  x1, [x9]
	adr_l x9, g_lprefix_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x0, k_count
	bl   w_cstr
	adr_l x9, listing_n
	ldr  x1, [x9]                    // w_uint: x1 = val
	bl   w_uint
	adr_l x0, k_offset
	bl   w_cstr
	mov  x1, #0
	bl   w_uint
	adr_l x0, k_entries
	bl   w_cstr
	adr_l x9, listing_n
	ldr  x1, [x9]                    // w_map_hdr: x1 = count
	bl   w_map_hdr
	mov  x19, #0                     // i (r12)
.Lel_loop:
	adr_l x9, listing_n
	ldr  x9, [x9]
	cmp  x19, x9
	b.hs .Lel_donemap
	mov  x9, x19
	lsl  x9, x9, #5
	adr_l x20, listing_ents          // r13
	add  x20, x20, x9                // entry
	ldr  x1, [x20]                  // seg ptr
	ldr  x2, [x20, #8]             // seg len
	bl   w_txt                       // key = segment
	mov  x1, #2
	bl   w_map
	adr_l x0, k_hash
	bl   w_cstr
	ldr  x9, [x20, #16]           // hash ptr
	cbz  x9, .Lel_null
	mov  x1, x9
	mov  x2, #33
	bl   w_bstr
	b    .Lel_haschild
.Lel_null:
	mov  w9, #0xf6                   // CBOR null
	strb w9, [x24]
	add  x24, x24, #1
.Lel_haschild:
	adr_l x0, k_has_children
	bl   w_cstr
	ldr  x9, [x20, #24]
	cbz  x9, .Lel_false
	mov  w9, #0xf5                   // true
	strb w9, [x24]
	add  x24, x24, #1
	b    .Lel_next
.Lel_false:
	mov  w9, #0xf4                   // false
	strb w9, [x24]
	add  x24, x24, #1
.Lel_next:
	add  x19, x19, #1
	b    .Lel_loop
.Lel_donemap:
	adr_l x9, b_list_data
	sub  x23, x24, x9                // r14 = data len
	adr_l x0, t_listing
	mov  x1, #19
	adr_l x2, b_list_data
	mov  x3, x23
	adr_l x4, list_data_ch
	bl   ec_content_hash
	// ---- build the listing entity blob, hand to send_get_ok ----
	adr_l x24, b_list_env            // r15 = cursor
	adr_l x0, t_listing
	adr_l x1, b_list_data
	mov  x2, x23
	adr_l x3, list_data_ch
	bl   w_entity
	adr_l x9, b_list_env
	sub  x1, x24, x9                 // entity len (send_get_ok: x1 = len)
	adr_l x0, b_list_env             // ptr
	bl   send_get_ok
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// emit_sorted_included(x0 = count, x1 = table ptr) — emit an `included` CBOR map whose
// entries are sorted by their 33-byte key (ECF §4.2 canonical order). Each table entry is
// 40 bytes: [0]=key_ptr [8]=type_cstr [16]=data_ptr [24]=data_len [32]=chash_ptr.
// Emits via the global x24 cursor (w_map/w_bstr/w_entity), so x24 is left as the cursor.
	.type emit_sorted_included, %function
emit_sorted_included:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x20, x1                     // table ptr (r12)
	and  x21, x0, #0xff              // count (r13, zero-extended byte)
	// ---- bubble sort by 33-byte key ----
	mov  x22, x21                    // n (rcx) — sort bound
.Lesi_outer:
	cmp  x22, #1
	b.le .Lesi_sorted
	mov  x19, #0                     // j = 0 (rbx)
.Lesi_inner:
	sub  x9, x22, #1                 // n-1
	cmp  x19, x9
	b.hs .Lesi_outer_dec
	mov  x9, x19
	mov  x10, #40
	mul  x9, x9, x10
	add  x23, x20, x9                // &entry[j] (r14)
	ldr  x0, [x23]                  // key[j]
	ldr  x1, [x23, #40]           // key[j+1]
	bl   mcmp33                      // w0 = signed byte diff
	cmp  w0, #0
	b.le .Lesi_noswap
	// swap the two 40-byte entries (5 quads)
	ldr  x9, [x23]      ; ldr x10, [x23, #40] ; str x10, [x23]      ; str x9, [x23, #40]
	ldr  x9, [x23, #8]  ; ldr x10, [x23, #48] ; str x10, [x23, #8]  ; str x9, [x23, #48]
	ldr  x9, [x23, #16] ; ldr x10, [x23, #56] ; str x10, [x23, #16] ; str x9, [x23, #56]
	ldr  x9, [x23, #24] ; ldr x10, [x23, #64] ; str x10, [x23, #24] ; str x9, [x23, #64]
	ldr  x9, [x23, #32] ; ldr x10, [x23, #72] ; str x10, [x23, #32] ; str x9, [x23, #72]
.Lesi_noswap:
	add  x19, x19, #1
	b    .Lesi_inner
.Lesi_outer_dec:
	sub  x22, x22, #1
	b    .Lesi_outer
.Lesi_sorted:
	// ---- emit map(count) then each entry ----
	mov  x1, x21                     // w_map: x1 = count
	bl   w_map
	mov  x19, #0                     // i = 0 (rbx)
.Lesi_emit:
	cmp  x19, x21
	b.hs .Lesi_done
	mov  x9, x19
	mov  x10, #40
	mul  x9, x9, x10
	add  x23, x20, x9                // &entry[i]
	ldr  x1, [x23]                  // key ptr
	mov  x2, #33
	bl   w_bstr
	ldr  x0, [x23, #8]            // type cstr
	ldr  x1, [x23, #16]           // data ptr
	ldr  x2, [x23, #24]           // data len
	ldr  x3, [x23, #32]           // chash ptr
	bl   w_entity
	add  x19, x19, #1
	b    .Lesi_emit
.Lesi_done:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// check_hello_negotiation(x0 = exec data map) -> x0 = 1 if the hello was rejected (a 400
// was sent), else 0. Rejects when params.data.hash_formats excludes "ecfv1-sha256" or
// params.data.key_types excludes "ed25519" (§4.5). Absent fields are not rejected (the
// happy path advertises our sets); this only fires on an explicit disjoint advertisement.
	.type check_hello_negotiation, %function
check_hello_negotiation:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x0                     // exec data map (r12)
	// params = map_find(exec, "params", 6)
	mov  x0, x19
	adr_l x1, k_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lhn_ok
	// pdata = map_find(params, "data", 4)
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lhn_ok
	mov  x20, x0                     // pdata (rbx)
	// hash_formats present? require "ecfv1-sha256"
	mov  x0, x20
	adr_l x1, k_hfmts
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lhn_kt                 // absent → skip (don't reject)
	adr_l x1, v_ecfv1
	mov  x2, #12                     // array_contains: x0=array, x1=needle, x2=len
	bl   array_contains
	cbnz x0, .Lhn_kt
	mov  x0, #400
	adr_l x1, ec_incompat_hf
	bl   send_error
	mov  x0, #1
	b    .Lhn_ret
.Lhn_kt:
	// key_types present? require "ed25519"
	mov  x0, x20
	adr_l x1, k_ktypes
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lhn_pid                // absent → still classify the peer_id's key-type
	adr_l x1, v_ed25519
	mov  x2, #7
	bl   array_contains
	cbnz x0, .Lhn_pid
	mov  x0, #400
	adr_l x1, ec_unsup_kt
	bl   send_error
	mov  x0, #1
	b    .Lhn_ret
.Lhn_pid:
	// §4.4/§7.1 agility: the hello's peer_id encodes its key-type as a multihash varint
	// prefix. Parse it; anything but ed25519 (key_type 1) — or an unparseable id — is an
	// unsupported algorithm → 400 unsupported_key_type (AGILITY-UNKNOWN-1, key_type 0xFD).
	mov  x0, x20                     // pdata
	adr_l x1, k_peerid
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lhn_ok                 // no peer_id → nothing to classify
	bl   get_text                    // x0 = ptr, x2 = len
	mov  x1, x2                      // len -> x1 (ec_peerid_parse: x0=ptr, x1=len, ...)
	adr_l x2, g_pid_kt
	adr_l x3, g_pid_ht
	adr_l x4, b_pid_digest
	adr_l x5, g_pid_dlen
	bl   ec_peerid_parse
	cbnz w0, .Lhn_bad_kt             // parse failure → unsupported
	adr_l x9, g_pid_kt
	ldr  x9, [x9]
	cmp  x9, #1                      // 1 = ed25519 (the core floor)
	b.eq .Lhn_ok
.Lhn_bad_kt:
	mov  x0, #400
	adr_l x1, ec_unsup_kt
	bl   send_error
	mov  x0, #1
	b    .Lhn_ret
.Lhn_ok:
	mov  x0, #0
.Lhn_ret:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// array_contains(x0 = array value ptr, x1 = needle ptr, x2 = needle len) -> x0 = 1|0.
// Iterates a CBOR text array; matches by exact bytes. (Elements assumed text — true for
// hash_formats / key_types; a non-text element just won't match.)
	.type array_contains, %function
array_contains:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x21, x1                     // needle ptr (r13)
	mov  x22, x2                     // needle len (r14)
	bl   read_head                   // x0=after-head, x1=major(4), x2=count
	mov  x19, x0                     // cursor (r12)
	mov  x20, x2                     // remaining count (rbx)
.Lac_l:
	cbz  x20, .Lac_no
	mov  x0, x19
	bl   read_head                   // x0=text start, x2=len (major 3)
	mov  x9, x0                      // element start (survives memeq)  (r8)
	add  x19, x0, x2                 // advance cursor past element text
	cmp  x2, x22
	b.ne .Lac_next
	mov  x1, x9                      // element start
	mov  x0, x21                     // needle ptr ; x2 already = len
	bl   memeq
	cbnz x0, .Lac_yes
.Lac_next:
	sub  x20, x20, #1
	b    .Lac_l
.Lac_yes:
	mov  x0, #1
	b    .Lac_ret
.Lac_no:
	mov  x0, #0
.Lac_ret:
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret
// =====================================================================
// verify_get_auth(x0 = exec data map) -> x0 = 0 authorized, 1 rejected (401 sent).
// §5.2 auth-class (401) stage: the request must carry an `author`, that author's system/peer
// entity must be in `included` (→ its public_key), and `included` must hold a system/signature
// with signer=author and target=root.content_hash that Ed25519-verifies over that 33-byte
// hash. A missing author / unresolvable pubkey / absent-or-bad signature → 401
// authentication_failed. (Capability-class 403 checks are a separate, later stage.)
	.type verify_get_auth, %function
verify_get_auth:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]         // x19=author ptr(rbx), x20=included(r12)
	stp  x21, x22, [sp, #32]         // x21=root_ch(r13), x22=pubkey(r14)
	str  x24, [sp, #48]             // x24=exec data map (r15) — preserve global cursor slot
	mov  x24, x0                    // exec data map
	// A. author present?
	mov  x0, x24
	adr_l x1, k_author
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lvga_401
	bl   get_text                   // x0=author ptr, x2=33
	mov  x19, x0                    // author ptr
	// B. included present?
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvga_401
	mov  x20, x0                    // included map
	// C. author's peer entity in included → public_key
	mov  x0, x20
	mov  x1, x19
	bl   included_find_by_key
	cbz  x0, .Lvga_401
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvga_401
	adr_l x1, ka_pubkey
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvga_401
	bl   get_text                   // x0=pubkey ptr, x2=32
	mov  x22, x0                    // pubkey ptr
	// D. root.content_hash
	adr_l x0, b_req
	adr_l x1, k_root
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvga_401
	adr_l x1, k_chash
	mov  x2, #12
	bl   map_find
	cbz  x0, .Lvga_401
	bl   get_text                   // x0=root_ch ptr, x2=33
	mov  x21, x0                    // root_ch ptr
	// E. request signature: signer==author, target==root_ch
	mov  x0, x20                    // included
	mov  x1, x19                    // author
	mov  x2, x21                    // root_ch
	bl   find_req_sig               // x0 = 64-byte signature ptr | 0
	cbz  x0, .Lvga_401
	// F. Ed25519 verify over root_ch
	mov  x3, x0                     // signature
	mov  x0, x22                    // pubkey
	mov  x1, x21                    // message = root_ch
	mov  x2, #33
	bl   ec_ed25519_verify
	cbnz w0, .Lvga_401
	mov  x0, #0                     // authorized
	b    .Lvga_ret
.Lvga_401:
	mov  x0, #401
	adr_l x1, ec_auth_failed
	bl   send_error
	mov  x0, #1
.Lvga_ret:
	ldr  x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// verify_multisig_granter(x0 = granter map, x1 = cap_hash ptr, x2 = included) -> x0 = 0
// accept / 1 reject. §5.5 M3/M4/M6: threshold ≥ 2, N ≥ 2, 2 ≤ threshold ≤ N, parent null,
// signers distinct, THIS peer ∈ signers, and ≥ threshold distinct signers each hold a valid
// Ed25519 signature over the token hash. Fail-closed on any structural miss.
	.type verify_multisig_granter, %function
verify_multisig_granter:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]         // x19=i/loop(rbx), x20=included(r12)
	stp  x21, x22, [sp, #32]         // x21=cap_hash(r13), x22=signer cursor(r14)
	str  x24, [sp, #48]             // x24=N(r15) — preserve global cursor slot
	mov  x21, x1                    // cap_hash
	mov  x20, x2                    // included
	mov  x19, x0                    // granter map (temporarily in rbx→x19)
	// threshold
	mov  x0, x19
	adr_l x1, ka_threshold
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lvms_reject
	bl   read_head                  // x2 = threshold
	adr_l x9, g_ms_thresh
	str  x2, [x9]
	cmp  x2, #2
	b.lo .Lvms_reject               // threshold < 2
	// (M3's root-only rule is enforced by the caller, against the TOKEN's `parent` field —
	// testing the GRANTER map for a `parent` key is vacuous, since {signers, threshold}
	// never carries one.)
	// signers array
	mov  x0, x19
	adr_l x1, ka_signers
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lvms_reject
	bl   read_head                  // x0=first elem, x1=major, x2=count
	cmp  x1, #4
	b.ne .Lvms_reject
	mov  x24, x2                    // N
	mov  x22, x0                    // signer cursor
	cmp  x24, #2
	b.lo .Lvms_reject               // N < 2
	cmp  x24, #32
	b.hi .Lvms_reject               // bound the scratch array
	adr_l x9, g_ms_thresh
	ldr  x9, [x9]
	cmp  x9, x24
	b.hi .Lvms_reject               // threshold > N
	// collect signer-hash pointers into g_ms_sigs[0..N)
	mov  x19, #0                    // i
.Lvms_collect:
	cmp  x19, x24
	b.hs .Lvms_collected
	mov  x0, x22
	bl   get_text                   // x0 = signer ptr (33)
	adr_l x9, g_ms_sigs
	str  x0, [x9, x19, lsl #3]
	mov  x0, x22
	bl   skip_value
	mov  x22, x0
	add  x19, x19, #1
	b    .Lvms_collect
.Lvms_collected:
	// distinctness — reject if any two signers are equal
	mov  x19, #0                    // i
.Lvms_di:
	cmp  x19, x24
	b.hs .Lvms_distinct_ok
	add  x22, x19, #1               // j = i+1
.Lvms_dj:
	cmp  x22, x24
	b.hs .Lvms_di_next
	adr_l x9, g_ms_sigs
	ldr  x0, [x9, x19, lsl #3]
	ldr  x1, [x9, x22, lsl #3]
	mov  x2, #33
	bl   memeq
	cbnz x0, .Lvms_reject           // duplicate signer
	add  x22, x22, #1
	b    .Lvms_dj
.Lvms_di_next:
	add  x19, x19, #1
	b    .Lvms_di
.Lvms_distinct_ok:
	adr_l x9, g_ms_valid
	str  xzr, [x9]
	adr_l x9, g_ms_local
	str  xzr, [x9]
	mov  x19, #0                    // i
.Lvms_vloop:
	cmp  x19, x24
	b.hs .Lvms_counted
	adr_l x9, g_ms_sigs
	ldr  x22, [x9, x19, lsl #3]     // signer i ptr
	// local ∈ signers?
	mov  x0, x22
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lvms_notlocal
	mov  x9, #1
	adr_l x10, g_ms_local
	str  x9, [x10]
.Lvms_notlocal:
	// a valid signature by signer i over cap_hash?
	mov  x0, x20
	mov  x1, x22
	mov  x2, x21
	bl   find_req_sig               // x0 = 64-byte sig ptr | 0
	cbz  x0, .Lvms_vnext
	adr_l x9, g_ms_sigptr
	str  x0, [x9]
	// signer i public_key from its system/peer in included
	mov  x0, x20
	mov  x1, x22
	bl   included_find_by_key
	cbz  x0, .Lvms_vnext
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvms_vnext
	adr_l x1, ka_pubkey
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvms_vnext
	bl   get_text                   // x0 = pubkey ptr
	mov  x1, x21                    // message = cap_hash
	mov  x2, #33
	adr_l x9, g_ms_sigptr
	ldr  x3, [x9]                   // signature
	bl   ec_ed25519_verify
	cbnz w0, .Lvms_vnext            // invalid signature
	adr_l x9, g_ms_valid
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
.Lvms_vnext:
	add  x19, x19, #1
	b    .Lvms_vloop
.Lvms_counted:
	adr_l x9, g_ms_local
	ldr  x9, [x9]
	cbz  x9, .Lvms_reject           // THIS peer must be a co-signer
	adr_l x9, g_ms_valid
	ldr  x9, [x9]
	adr_l x10, g_ms_thresh
	ldr  x10, [x10]
	cmp  x9, x10
	b.lo .Lvms_reject               // fewer than threshold valid signatures
	mov  x0, #0                     // accept
	b    .Lvms_ret
.Lvms_reject:
	mov  x0, #1
.Lvms_ret:
	ldr  x24, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// §5.5a canonicalization + §5.6 attenuation — the delegation-chain interior.
// (Port of asm-x86_64/src/dispatch.s; same protocol logic, AAPCS64 registers.)
// =====================================================================
//
// peerid_of(x0 = included, x1 = hash33, x2 = out ptr, x3 = out_len ptr) -> x0 = 1|0.
// The §5.5a canonicalization FRAME for a link is its granter's peer_id, which is NOT on
// the wire: it is derived from the granter's system/peer entity in `included` — the same
// entity the link's signature is verified against — by re-running the base58 peer-id
// format over its public_key.
	.type peerid_of, %function
peerid_of:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x2                     // out
	mov  x20, x3                     // out_len ptr
	bl   included_find_by_key
	cbz  x0, .Lpio_no
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lpio_no
	adr_l x1, ka_pubkey
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lpio_no
	bl   get_text                    // x0 = pubkey ptr, x2 = len
	cmp  x2, #32
	b.ne .Lpio_no
	mov  x21, x0
	mov  x0, #1                      // key_type = ed25519
	mov  x1, #0                      // hash_type = 0 (identity)
	mov  x2, x21
	mov  x3, #32
	mov  x4, x19
	mov  x5, #128
	mov  x6, x20
	bl   ec_peerid_format
	cbnz w0, .Lpio_no
	mov  x0, #1
	b    .Lpio_ret
.Lpio_no:
	mov  x0, #0
.Lpio_ret:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// canon(x0 = pattern, x1 = len, x2 = frame, x3 = frame len, x4 = out) -> x0 = out len.
// §5.5a: a leading "/" means the pattern already names a peer position — copy verbatim;
// anything else is peer-RELATIVE and becomes "/" + frame + "/" + pattern.
// Bare "*" gets NO special case and deliberately must not: it falls out of the general rule
// as "/{frame}/*", which is exactly what §5.5a says it means — the granter's own namespace,
// never a universal cross-peer wildcard. Special-casing it is how the bare-star-is-universal
// defect (A-PD-017, and swift/sql's frame over-scoping) gets built.
	.type canon, %function
canon:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x19, x0                     // pattern
	mov  x20, x1                     // pattern len
	mov  x21, x2                     // frame
	mov  x22, x3                     // frame len
	mov  x23, x4                     // out
	cbz  x20, .Lcn_rel
	ldrb w9, [x19]
	cmp  w9, #0x2f
	b.ne .Lcn_rel
	mov  x0, x23
	mov  x1, x19
	mov  x2, x20
	bl   mcpy
	mov  x0, x20
	b    .Lcn_ret
.Lcn_rel:
	mov  w9, #0x2f
	strb w9, [x23]
	add  x0, x23, #1
	mov  x1, x21
	mov  x2, x22
	bl   mcpy                        // x0 = dst + frame len
	mov  w9, #0x2f
	strb w9, [x0]
	add  x0, x0, #1
	mov  x1, x19
	mov  x2, x20
	bl   mcpy
	sub  x0, x0, x23                 // total canonical length
.Lcn_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// pat_covers(x0 = child pat, x1 = child len, x2 = parent pat, x3 = parent len) -> x0 = 1|0.
// Both canonical, both absolute. Segment-wise:
//   parent "*" as the LAST segment → covers everything remaining
//   parent "*" mid-pattern         → covers exactly one child segment, whatever it is
//   parent literal                 → the child segment must be that literal; a child "*"
//                                    here is BROADER than the parent and is refused
// Both exhausted together → covered; either alone → not covered.
	.type pat_covers, %function
pat_covers:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	stp  x26, x27, [sp, #64]
	str  x28, [sp, #80]
	mov  x19, x0                     // child ptr
	mov  x20, x1                     // child len
	mov  x21, x2                     // parent ptr
	mov  x22, x3                     // parent len
	cbz  x20, .Lpc_no
	cbz  x22, .Lpc_no
	ldrb w9, [x19]
	cmp  w9, #0x2f
	b.ne .Lpc_no
	ldrb w9, [x21]
	cmp  w9, #0x2f
	b.ne .Lpc_no
	mov  x23, #1                     // ci
	mov  x25, #1                     // pi
.Lpc_loop:
	cmp  x25, x22
	b.lo .Lpc_pseg
	cmp  x23, x20                    // parent exhausted → covered iff child is too
	b.hs .Lpc_yes
	b    .Lpc_no
.Lpc_pseg:
	// Read the PARENT segment BEFORE testing whether the child is exhausted: a trailing "*"
	// covers the remainder INCLUDING the empty one. "/{peer}/*" authorizes that peer's
	// namespace, and listing the namespace's own root ("/{peer}/") is inside it, not above
	// it. Testing child-exhaustion first refuses every root listing while every deeper path
	// still works, which reads as a permissions bug rather than a matcher bug.
	add  x26, x21, x25               // ps
	mov  x27, #0                     // pl
.Lpc_pscan:
	add  x9, x25, x27
	cmp  x9, x22
	b.hs .Lpc_pdone
	ldrb w10, [x26, x27]
	cmp  w10, #0x2f
	b.eq .Lpc_pdone
	add  x27, x27, #1
	b    .Lpc_pscan
.Lpc_pdone:
	cmp  x27, #1
	b.ne .Lpc_child
	ldrb w10, [x26]
	cmp  w10, #0x2a
	b.ne .Lpc_child
	add  x9, x25, x27
	cmp  x9, x22
	b.hs .Lpc_yes                    // trailing "*" — covers the rest, empty included
.Lpc_child:
	cmp  x23, x20
	b.hs .Lpc_no                     // child exhausted under a non-trailing-star parent
	add  x28, x19, x23               // cs
	mov  x9, #0                      // cl (kept in x9 across the scan, saved below)
.Lpc_cscan:
	add  x10, x23, x9
	cmp  x10, x20
	b.hs .Lpc_cdone
	ldrb w11, [x28, x9]
	cmp  w11, #0x2f
	b.eq .Lpc_cdone
	add  x9, x9, #1
	b    .Lpc_cscan
.Lpc_cdone:
	mov  x2, x9                      // cl
	cmp  x27, #1
	b.ne .Lpc_literal
	ldrb w10, [x26]
	cmp  w10, #0x2a
	b.eq .Lpc_advance                // mid-pattern "*" — matches this one child segment
.Lpc_literal:
	cmp  x2, #1
	b.ne .Lpc_cmp
	ldrb w10, [x28]
	cmp  w10, #0x2a
	b.eq .Lpc_no                     // a "*" child under a literal parent is BROADER
.Lpc_cmp:
	cmp  x2, x27
	b.ne .Lpc_no
	mov  x0, x28
	mov  x1, x26
	bl   memeq                       // x2 = segment length
	cbz  x0, .Lpc_no
	mov  x2, x27                     // memeq clobbers nothing callee-saved; cl == pl here
.Lpc_advance:
	add  x23, x23, x2
	add  x23, x23, #1
	add  x25, x25, x27
	add  x25, x25, #1
	b    .Lpc_loop
.Lpc_yes:
	mov  x0, #1
	b    .Lpc_ret
.Lpc_no:
	mov  x0, #0
.Lpc_ret:
	ldr  x28, [sp, #80]
	ldp  x26, x27, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #96
	ret

// arr_subset_framed(x0 = sub array, x1 = super array) -> x0 = 1 if every element of `sub`
// is covered by some element of `super` under §5.5a framing. The two sides canonicalize
// against DIFFERENT frames — g_sfr_ptr/len for `sub`, g_qfr_ptr/len for `super` — which the
// caller sets, so the exclude direction reverses them without copying a frame.
	.type arr_subset_framed, %function
arr_subset_framed:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	stp  x26, x27, [sp, #64]
	str  x28, [sp, #80]
	mov  x25, x1                     // super array
	bl   read_head                   // x0 = sub array
	cmp  x1, #4
	b.ne .Lasf_no
	mov  x19, x0                     // sub cursor
	mov  x20, x2                     // sub remaining
.Lasf_outer:
	cbz  x20, .Lasf_yes
	mov  x0, x19
	bl   read_head                   // x0 = elem bytes, x2 = elem len
	mov  x21, x0
	mov  x22, x2
	add  x19, x0, x2
	sub  x20, x20, #1
	mov  x0, x21
	mov  x1, x22
	adr_l x9, g_sfr_ptr
	ldr  x2, [x9]
	adr_l x9, g_sfr_len
	ldr  x3, [x9]
	adr_l x4, b_canon_a
	bl   canon
	mov  x23, x0                     // canonical child length
	mov  x0, x25
	bl   read_head
	cmp  x1, #4
	b.ne .Lasf_no
	mov  x26, x0                     // super cursor
	mov  x27, x2                     // super remaining
.Lasf_inner:
	cbz  x27, .Lasf_no               // no super element covers this sub element
	mov  x0, x26
	bl   read_head
	mov  x28, x0
	mov  x9, x2
	add  x26, x0, x2
	sub  x27, x27, #1
	mov  x0, x28
	mov  x1, x9
	adr_l x9, g_qfr_ptr
	ldr  x2, [x9]
	adr_l x9, g_qfr_len
	ldr  x3, [x9]
	adr_l x4, b_canon_b
	bl   canon
	mov  x3, x0
	adr_l x0, b_canon_a
	mov  x1, x23
	adr_l x2, b_canon_b
	bl   pat_covers
	cbnz x0, .Lasf_outer
	b    .Lasf_inner
.Lasf_yes:
	mov  x0, #1
	b    .Lasf_ret
.Lasf_no:
	mov  x0, #0
.Lasf_ret:
	ldr  x28, [sp, #80]
	ldp  x26, x27, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #96
	ret

// set_frames_cp / set_frames_pc — point the sub/super frame pair at the child/parent frames
// in the given order. Clobbers x9/x10 only.
	.type set_frames_cp, %function
set_frames_cp:
	adr_l x9, g_cfr
	adr_l x10, g_sfr_ptr
	str  x9, [x10]
	adr_l x9, g_cfrlen
	ldr  x9, [x9]
	adr_l x10, g_sfr_len
	str  x9, [x10]
	adr_l x9, g_pfr
	adr_l x10, g_qfr_ptr
	str  x9, [x10]
	adr_l x9, g_pfrlen
	ldr  x9, [x9]
	adr_l x10, g_qfr_len
	str  x9, [x10]
	ret
	.type set_frames_pc, %function
set_frames_pc:
	adr_l x9, g_pfr
	adr_l x10, g_sfr_ptr
	str  x9, [x10]
	adr_l x9, g_pfrlen
	ldr  x9, [x9]
	adr_l x10, g_sfr_len
	str  x9, [x10]
	adr_l x9, g_cfr
	adr_l x10, g_qfr_ptr
	str  x9, [x10]
	adr_l x9, g_cfrlen
	ldr  x9, [x9]
	adr_l x10, g_qfr_len
	str  x9, [x10]
	ret

// dim_subset(x0 = child scope map, x1 = parent scope map, x2 = framed) -> x0 = 1|0.
// One scope dimension, child ⊆ parent. `framed` selects §5.5a canonicalization, which scopes
// the RESOURCE dimension ONLY — handlers/operations/peers are id-scope and take no frame.
// Over-applying the frame is the swift/sql defect: a universal parent grant stops covering
// any child grant the moment the two have different granters, and every delegated cap 403s.
// Both halves of the spec's scope_subset are here: child includes covered by parent includes,
// AND every parent exclude inherited by some child exclude.
	.type dim_subset, %function
dim_subset:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x19, x0                     // child scope
	mov  x20, x1                     // parent scope
	mov  x21, x2                     // framed
	mov  x0, x19
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lds_no
	mov  x22, x0                     // child include
	mov  x0, x20
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lds_no
	mov  x23, x0                     // parent include
	cbz  x21, .Lds_inc_plain
	bl   set_frames_cp               // sub ← child frame, super ← parent frame
	mov  x0, x22
	mov  x1, x23
	bl   arr_subset_framed
	b    .Lds_inc_done
.Lds_inc_plain:
	mov  x0, x22
	mov  x1, x23
	bl   array_subset_star
.Lds_inc_done:
	cbz  x0, .Lds_no
	// Exclude inheritance runs in the REVERSE direction from includes: each PARENT exclude
	// must be covered by some CHILD exclude, because the child must exclude at least as much
	// as its parent did. A child that simply drops the parent's exclude widens itself.
	mov  x0, x20
	adr_l x1, ka_exclude
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lds_yes                // parent excludes nothing → nothing to inherit
	mov  x23, x0                     // parent exclude
	mov  x0, x19
	adr_l x1, ka_exclude
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lds_no                 // parent excluded, child does not → widened
	mov  x22, x0                     // child exclude
	cbz  x21, .Lds_exc_plain
	bl   set_frames_pc               // sub ← parent frame, super ← child frame
	mov  x0, x23
	mov  x1, x22
	bl   arr_subset_framed
	b    .Lds_ret
.Lds_exc_plain:
	mov  x0, x23
	mov  x1, x22
	bl   array_subset_star
	b    .Lds_ret
.Lds_yes:
	mov  x0, #1
	b    .Lds_ret
.Lds_no:
	mov  x0, #0
.Lds_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// map_attenuated(x0 = from map | 0, x1 = to map | 0) -> x0 = 1|0.
// Every key of `from` must appear in `to` with a byte-identical value. Used twice, in
// opposite directions: CONSTRAINTS (every parent key must survive on the child — a dropped
// key widens it) and ALLOWANCES (every child key must already exist on the parent — an added
// key widens it). Absent `from` → vacuously attenuated.
	.type map_attenuated, %function
map_attenuated:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	cbz  x0, .Lma_yes
	mov  x25, x1                     // to
	bl   read_head                   // x0 = from
	cmp  x1, #5
	b.ne .Lma_no
	mov  x19, x0                     // cursor
	mov  x20, x2                     // pair count
	cbz  x20, .Lma_yes
	cbz  x25, .Lma_no
.Lma_loop:
	cbz  x20, .Lma_yes
	mov  x0, x19
	bl   read_head                   // x0 = key bytes, x2 = key len
	mov  x21, x0
	mov  x22, x2
	add  x19, x0, x2                 // value ptr
	mov  x0, x25
	mov  x1, x21
	mov  x2, x22
	bl   map_find
	cbz  x0, .Lma_no
	mov  x21, x0                     // the counterpart value
	mov  x0, x19
	bl   skip_value
	mov  x22, x0                     // next pair
	sub  x23, x0, x19                // this value's byte length
	mov  x0, x21
	bl   skip_value
	sub  x0, x0, x21                 // counterpart length
	cmp  x0, x23
	b.ne .Lma_no
	mov  x2, x23
	mov  x0, x19
	mov  x1, x21
	bl   memeq
	cbz  x0, .Lma_no
	mov  x19, x22
	sub  x20, x20, #1
	b    .Lma_loop
.Lma_yes:
	mov  x0, #1
	b    .Lma_ret
.Lma_no:
	mov  x0, #0
.Lma_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// grant_subset_framed(x0 = child grant, x1 = parent grant) -> x0 = 1|0.
// All four §5.6 scope dimensions plus constraints and allowances. Only RESOURCES is framed.
	.type grant_subset_framed, %function
grant_subset_framed:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x0                     // child grant
	mov  x20, x1                     // parent grant
	// handlers — id-scope, no frame
	mov  x0, x19
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x21, x0
	mov  x0, x20
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x1, x0
	mov  x0, x21
	mov  x2, #0
	bl   dim_subset
	cbz  x0, .Lgsf_no
	// operations — id-scope, no frame
	mov  x0, x19
	adr_l x1, ka_operations
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x21, x0
	mov  x0, x20
	adr_l x1, ka_operations
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x1, x0
	mov  x0, x21
	mov  x2, #0
	bl   dim_subset
	cbz  x0, .Lgsf_no
	// resources — THE framed dimension, and the only one
	mov  x0, x19
	adr_l x1, ka_resources
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lgsf_peers             // child names no resources → nothing to bound
	mov  x21, x0
	mov  x0, x20
	adr_l x1, ka_resources
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x1, x0
	mov  x0, x21
	mov  x2, #1
	bl   dim_subset
	cbz  x0, .Lgsf_no
.Lgsf_peers:
	// peers — id-scope; absent defaults to {include:[local_peer_id]} on BOTH sides, so an
	// absent-vs-absent pair is trivially a subset and needs no synthesised map.
	mov  x0, x19
	adr_l x1, ka_peers
	mov  x2, #5
	bl   map_find
	cbz  x0, .Lgsf_maps
	mov  x21, x0
	mov  x0, x20
	adr_l x1, ka_peers
	mov  x2, #5
	bl   map_find
	cbz  x0, .Lgsf_no
	mov  x1, x0
	mov  x0, x21
	mov  x2, #0
	bl   dim_subset
	cbz  x0, .Lgsf_no
.Lgsf_maps:
	// constraints: every parent key retained on the child, byte-equal
	mov  x0, x20
	adr_l x1, ka_constraints
	mov  x2, #11
	bl   map_find
	mov  x21, x0
	mov  x0, x19
	adr_l x1, ka_constraints
	mov  x2, #11
	bl   map_find
	mov  x1, x0
	mov  x0, x21
	bl   map_attenuated
	cbz  x0, .Lgsf_no
	// allowances: every child key pre-existing on the parent, byte-equal
	mov  x0, x19
	adr_l x1, ka_allowances
	mov  x2, #10
	bl   map_find
	mov  x21, x0
	mov  x0, x20
	adr_l x1, ka_allowances
	mov  x2, #10
	bl   map_find
	mov  x1, x0
	mov  x0, x21
	bl   map_attenuated
	b    .Lgsf_ret
.Lgsf_no:
	mov  x0, #0
.Lgsf_ret:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// is_attenuated(x0 = child token data, x1 = parent token data) -> x0 = 1|0.
// §5.6 with the per-link §5.5a frames already in g_cfr / g_pfr: every child grant covered by
// some parent grant, then the expiration rule.
	.type is_attenuated, %function
is_attenuated:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	stp  x26, x27, [sp, #64]
	mov  x19, x0                     // child token data
	mov  x20, x1                     // parent token data
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lia_no
	mov  x21, x0                     // child grants array
	mov  x0, x20
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lia_no
	mov  x22, x0                     // parent grants array
	mov  x0, x21
	bl   read_head
	cmp  x1, #4
	b.ne .Lia_no
	mov  x21, x0                     // child grant cursor
	mov  x23, x2                     // child grants remaining
.Lia_child:
	cbz  x23, .Lia_expiry
	mov  x0, x22
	bl   read_head
	cmp  x1, #4
	b.ne .Lia_no
	mov  x25, x0                     // parent cursor
	mov  x26, x2                     // parent grants remaining
.Lia_parent:
	cbz  x26, .Lia_no                // this child grant is covered by no parent grant
	mov  x0, x21
	mov  x1, x25
	bl   grant_subset_framed
	cbnz x0, .Lia_covered
	mov  x0, x25
	bl   skip_value
	mov  x25, x0
	sub  x26, x26, #1
	b    .Lia_parent
.Lia_covered:
	mov  x0, x21
	bl   skip_value
	mov  x21, x0
	sub  x23, x23, #1
	b    .Lia_child
.Lia_expiry:
	// §5.6 expiration, nil-vs-finite: a child with NO expires_at is INFINITE, and infinite
	// exceeds any finite parent. The permissive reading — treat the absent child field as
	// "inherits the parent's" — is the one a reader reaches by accident and is explicitly
	// non-conformant.
	mov  x0, x20
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lia_yes                // parent never expires → nothing to bound
	bl   read_head
	cbnz x1, .Lia_no                 // not a uint64 → unusable, never "absent"
	mov  x27, x2                     // parent expiry
	mov  x0, x19
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lia_no                 // infinite child under a finite parent
	bl   read_head
	cbnz x1, .Lia_no
	cmp  x2, x27
	b.hi .Lia_no
.Lia_yes:
	mov  x0, #1
	b    .Lia_ret
.Lia_no:
	mov  x0, #0
.Lia_ret:
	ldp  x26, x27, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #96
	ret

// caveats_ok(x0 = parent token data, x1 = child token data, x2 = depth) -> x0 = 1|0.
// §5.5 check_delegation_caveats. An absent block means there is nothing to enforce.
	.type caveats_ok, %function
caveats_ok:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x19, x1                     // child token data
	mov  x20, x2                     // depth
	adr_l x1, ka_deleg_caveats
	mov  x2, #18
	bl   map_find                    // x0 = parent token data
	cbz  x0, .Lco_yes
	mov  x21, x0                     // caveats map
	// no_delegation
	mov  x0, x21
	adr_l x1, ka_no_delegation
	mov  x2, #13
	bl   map_find
	cbz  x0, .Lco_depth
	ldrb w9, [x0]
	cmp  w9, #0xf5                   // CBOR true
	b.eq .Lco_no
.Lco_depth:
	// max_delegation_depth — denied when depth >= limit
	mov  x0, x21
	adr_l x1, ka_max_deleg_depth
	mov  x2, #20
	bl   map_find
	cbz  x0, .Lco_ttl
	bl   read_head
	cbnz x1, .Lco_no
	cmp  x20, x2
	b.hs .Lco_no
.Lco_ttl:
	// max_delegation_ttl — an infinite child exceeds any finite limit
	mov  x0, x21
	adr_l x1, ka_max_deleg_ttl
	mov  x2, #18
	bl   map_find
	cbz  x0, .Lco_yes
	bl   read_head
	cbnz x1, .Lco_no
	mov  x22, x2                     // limit
	mov  x0, x19
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lco_no                 // child never expires → unbounded ttl
	bl   read_head
	cbnz x1, .Lco_no
	mov  x23, x2                     // child expires_at
	mov  x0, x19
	adr_l x1, ka_created
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lco_no
	bl   read_head
	cbnz x1, .Lco_no
	cmp  x23, x2
	b.lo .Lco_yes                    // already expired at birth — bounded by anything
	sub  x23, x23, x2
	cmp  x23, x22
	b.hi .Lco_no
.Lco_yes:
	mov  x0, #1
	b    .Lco_ret
.Lco_no:
	mov  x0, #0
.Lco_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// link_temporal_ok(x0 = token data) -> x0 = 1|0, against g_now (§5.5 `t`, sampled once).
//
// The CAP-6a REPRESENTABILITY test runs FIRST and is the whole point: an accessor that
// answers "nothing" for both an ABSENT field and a PRESENT-but-not-uint64 one collapses
// MALFORMED into ABSENT — and absent means "no expiry", so that reading hands an immortal
// capability to whoever sent the malformed value. Here the two are distinguishable by
// construction: map_find answers ABSENT, read_head's major answers REPRESENTABLE. CAP-6a
// covers THREE fields, and created_at is the one an audit shaped around expiry checks
// misses. (A bignum can only reach a peer as a major-type-6 tag and is refused at decode;
// what arrives here is the negative form, major type 1.)
	.type link_temporal_ok, %function
link_temporal_ok:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	mov  x19, x0
	adr_l x1, ka_created
	mov  x2, #10
	bl   map_find
	cbz  x0, .Llt_nb
	bl   read_head
	cbnz x1, .Llt_no
.Llt_nb:
	mov  x0, x19
	adr_l x1, ka_notbefore
	mov  x2, #10
	bl   map_find
	cbz  x0, .Llt_exp
	bl   read_head
	cbnz x1, .Llt_no
	adr_l x9, g_now
	ldr  x9, [x9]
	cmp  x9, x2
	b.lo .Llt_no                     // now < not_before
.Llt_exp:
	mov  x0, x19
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Llt_yes
	bl   read_head
	cbnz x1, .Llt_no
	// §5.6 CAP-6: expiry is an EXCLUSIVE upper bound — expired when now >= expires_at. This
	// pairs with ttl_ms:0 minting expires_at == created_at, which must be expired at every
	// observable instant rather than valid for one and racing.
	adr_l x9, g_now
	ldr  x9, [x9]
	cmp  x9, x2
	b.hs .Llt_no
.Llt_yes:
	mov  x0, #1
	b    .Llt_ret
.Llt_no:
	mov  x0, #0
.Llt_ret:
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// =====================================================================
// verify_get_cap(x0 = exec data map) -> x0 = 0 authorized, 1 rejected (403/401 sent).
// §5.2 capability-class + §5.5 delegation-chain verification.
//
// Walks capability → parent → … → root, validating EVERY link: content-hash integrity,
// revocation, grantee resolution, temporal validity (CAP-6a representability first), and the
// granter's signature. For every non-root link it additionally checks the parent linkage
// (parent.grantee == child.granter), §5.6 attenuation under §5.5a per-link granter frames,
// and the parent's delegation caveats. The ROOT's granter must be this peer — that check has
// not gone away, it has moved to the END of the walk where it belongs instead of standing in
// for the walk. A fail-closed root-trust gate answers about ten reject-direction chain
// vectors correctly for a reason unrelated to what they test, and refuses CAP-5/CAP-6/CAP-6a
// two gates before the mint they are named after.
	.type verify_get_cap, %function
// x19=included, x20=author, x21=cur hash, x22=depth, x23=child token data (ctd),
// x25=this link's token data (td), x26=this link's granter, x27=scratch. x24 is the
// global writer cursor and is never touched here.
verify_get_cap:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	stp  x26, x27, [sp, #64]
	str  x28, [sp, #80]
	mov  x28, x0                     // exec data map
	// capability present?
	adr_l x1, k_capability
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvgc_403
	bl   get_text                    // x0 = cap_hash ptr, x2 = len
	cmp  x2, #33
	b.ne .Lvgc_403
	mov  x21, x0                     // cur = the presented capability hash
	// author (verify_get_auth already ensured present)
	mov  x0, x28
	adr_l x1, k_author
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lvgc_403
	bl   get_text
	mov  x20, x0                     // author ptr
	// included
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvgc_403
	mov  x19, x0                     // included
	mov  x22, #0                     // depth
	mov  x23, #0                     // child token data (none yet)
	// §5.5 v7.76: `t` is sampled ONCE per verdict and never re-sampled per link — otherwise
	// the verdict depends on wall-clock drift within a single walk.
	bl   now_ms
	adr_l x9, g_now
	str  x0, [x9]
// ---------------------------------------------------------------- the walk
.Lvgc_walk:
	mov  x0, x19
	mov  x1, x21
	bl   included_find_by_key
	cbz  x0, .Lvgc_403               // capability_not_in_included
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvgc_403
	mov  x25, x0                     // td — this link's token data map
	// integrity: the link's data must hash to the hash we followed to reach it. A token whose
	// bytes were altered after signing no longer hashes to its key → 403.
	bl   skip_value
	sub  x3, x0, x25                 // data byte length (arg4)
	adr_l x0, ta_token
	mov  x1, #23
	mov  x2, x25
	adr_l x4, g_link_ch
	bl   ec_content_hash
	adr_l x0, g_link_ch
	mov  x1, x21
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lvgc_403               // recomputed hash ≠ the key we followed → substituted
	// §6.9a — revocation is PER LINK: revoking an intermediate kills everything under it.
	mov  x0, x21
	bl   is_revoked
	cbnz x0, .Lvgc_403
	// grantee present, 33 bytes, and resolving to a present system/peer — per link, not just
	// at the leaf. An unresolvable grantee is the §5.2 / PR-3 single-401 carve-out, NOT 403.
	mov  x0, x25
	adr_l x1, ka_grantee
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lvgc_403
	bl   get_text
	cmp  x2, #33
	b.ne .Lvgc_403
	mov  x26, x0                     // grantee ptr (x26 becomes the granter below)
	mov  x0, x19
	mov  x1, x26
	bl   included_find_by_key
	cbz  x0, .Lvgc_grantee_401
	adr_l x1, k_type
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvgc_grantee_401
	bl   get_text
	cmp  x2, #11
	b.ne .Lvgc_grantee_401
	adr_l x1, ta_peer
	mov  x2, #11
	bl   memeq
	cbz  x0, .Lvgc_grantee_401
	// linkage: the LEAF is granted to the request author; every parent is granted to the
	// granter of the link below it (g_pgee carries that hash across the hop).
	mov  x0, x26
	cbz  x22, .Lvgc_link_leaf
	adr_l x1, g_pgee
	b    .Lvgc_link_cmp
.Lvgc_link_leaf:
	mov  x1, x20                     // author
.Lvgc_link_cmp:
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lvgc_403               // grantee_author_mismatch / broken chain linkage
	// temporal validity of THIS link (CAP-6a representability first)
	mov  x0, x25
	bl   link_temporal_ok
	cbz  x0, .Lvgc_403
	// granter
	mov  x0, x25
	adr_l x1, ka_granter
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lvgc_403
	mov  x26, x0                     // granter value ptr
	bl   read_head                   // x1 = major type
	cmp  x1, #5
	b.ne .Lvgc_single_granter
	// §3.6 K-of-N multi-granter. M3 structural validity runs BEFORE any signature check, so a
	// violation surfaces as 403 capability_denied rather than as a signature failure.
	// Multi-sig is ROOT-ONLY: a multi-granter link carrying a parent is structurally invalid.
	mov  x0, x25
	adr_l x1, ka_parent
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lvgc_ms_root
	ldrb w9, [x0]                    // CBOR null is "no parent"
	cmp  w9, #0xf6
	b.ne .Lvgc_403
.Lvgc_ms_root:
	// A quorum root has no single granter peer_id, so §5.5a has no frame to canonicalize its
	// resource patterns against. Rather than invent one, a K-of-N root is accepted only when
	// it is the capability actually PRESENTED (depth 0), where no attenuation comparison is
	// needed. A chain whose ROOT is K-of-N is refused, and that limit is written here rather
	// than left to be discovered.
	cbnz x22, .Lvgc_403
	mov  x0, x26
	mov  x1, x21
	mov  x2, x19
	bl   verify_multisig_granter
	cbnz x0, .Lvgc_403
	b    .Lvgc_ok                    // quorum met — the chain terminates here
.Lvgc_single_granter:
	mov  x0, x26
	bl   get_text
	cmp  x2, #33
	b.ne .Lvgc_403
	mov  x26, x0                     // granter hash
	// signature over THIS link, by THIS link's granter
	mov  x0, x19
	mov  x1, x26
	bl   included_find_by_key
	cbz  x0, .Lvgc_403
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvgc_403
	adr_l x1, ka_pubkey
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvgc_403
	bl   get_text
	mov  x27, x0                     // granter pubkey (survives find_req_sig)
	mov  x0, x19
	mov  x1, x26
	mov  x2, x21
	bl   find_req_sig                // x0 = 64-byte sig ptr | 0
	cbz  x0, .Lvgc_403               // unsigned / forged
	mov  x3, x0
	mov  x0, x27
	mov  x1, x21
	mov  x2, #33
	bl   ec_ed25519_verify
	cbnz w0, .Lvgc_403
	// this link's §5.5a frame = its granter's peer_id
	mov  x0, x19
	mov  x1, x26
	adr_l x2, g_pfr
	adr_l x3, g_pfrlen
	bl   peerid_of
	cbz  x0, .Lvgc_403
	// attenuation + caveats against the child we arrived from
	cbz  x22, .Lvgc_rootcheck
	mov  x0, x23                     // ctd
	mov  x1, x25
	bl   is_attenuated
	cbz  x0, .Lvgc_403
	mov  x0, x25
	mov  x1, x23
	sub  x2, x22, #1
	bl   caveats_ok
	cbz  x0, .Lvgc_403
.Lvgc_rootcheck:
	mov  x0, x25
	adr_l x1, ka_parent
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lvgc_root
	ldrb w9, [x0]                    // an explicit null parent is a root
	cmp  w9, #0xf6
	b.eq .Lvgc_root
	mov  x27, x0                     // parent hash value ptr
	// carry the child state across the hop: its data, its granter, and its frame
	mov  x23, x25                    // ctd = this link
	adr_l x0, g_pgee
	mov  x1, x26
	mov  x2, #33
	bl   mcpy
	adr_l x0, g_cfr
	adr_l x1, g_pfr
	mov  x2, #128
	bl   mcpy
	adr_l x9, g_pfrlen
	ldr  x9, [x9]
	adr_l x10, g_cfrlen
	str  x9, [x10]
	mov  x0, x27
	bl   get_text
	cmp  x2, #33
	b.ne .Lvgc_403
	mov  x21, x0                     // cur = parent
	add  x22, x22, #1
	// §5.5 collect_authority_chain bounds depth at 64. chain_depth_check already answers 400
	// chain_depth_exceeded ahead of this walk, so this is the belt to that braces — it exists
	// so the loop cannot run unbounded if the walk is ever reached by another path.
	cmp  x22, #64
	b.hi .Lvgc_403
	b    .Lvgc_walk
.Lvgc_root:
	// §5.5 root trust: the chain must terminate at a capability THIS peer granted. The check
	// has not gone away — it is here, at the end of the walk, instead of standing in for it.
	mov  x0, x26
	adr_l x1, g_identity_hash
	mov  x2, #33
	bl   memeq
	cbz  x0, .Lvgc_403
.Lvgc_ok:
	mov  x0, #0                      // authorized
	b    .Lvgc_ret
.Lvgc_403:
	mov  x0, #403
	adr_l x1, ec_cap_denied
	bl   send_error
	mov  x0, #1
	b    .Lvgc_ret
.Lvgc_grantee_401:
	mov  x0, #401
	adr_l x1, ec_unresolvable_grantee
	bl   send_error
	mov  x0, #1
.Lvgc_ret:
	ldr  x28, [sp, #80]
	ldp  x26, x27, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #96
	ret

// =====================================================================
// is_peer_id(x0 = ptr, x1 = len) -> x0 = 1 if len >= 46 and every byte is in the Base58
// alphabet (§5.4 is_peer_id: Base58(key_type||hash_type||digest), 46 chars is the minimum
// for the smallest supported algorithm — Ed25519+SHA-256), else 0. Used by extract_peer
// (derive_handler below) to decide whether a uri's first path segment is a real peer id.
// Ported from asm-x86_64/src/dispatch.s (rdi/rsi/rbx/r12/r13/r14 -> x0/x1/x9/x19/x20/x21).
	.globl is_peer_id
	.type is_peer_id, %function
is_peer_id:
	cmp  x1, #46
	b.lo .Lipi_no
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x0                     // ptr
	mov  x20, x1                     // len
	mov  x21, #0                     // i
.Lipi_loop:
	cmp  x21, x20
	b.hs .Lipi_yes
	ldrb w9, [x19, x21]
	adr_l x10, s_base58_alpha
	mov  x11, #0
.Lipi_scan:
	cmp  x11, #58
	b.hs .Lipi_no_pop
	ldrb w12, [x10, x11]
	cmp  w12, w9
	b.eq .Lipi_found
	add  x11, x11, #1
	b    .Lipi_scan
.Lipi_found:
	add  x21, x21, #1
	b    .Lipi_loop
.Lipi_no_pop:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	mov  x0, #0
	ret
.Lipi_yes:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	mov  x0, #1
	ret
.Lipi_no:
	mov  x0, #0
	ret

// =====================================================================
// derive_handler(x0 = exec data map) — set g_handler_ptr/g_handler_len to the request's
// target handler, parsed from data.uri by stripping the "entity://<peer_id>/" prefix (scheme
// + authority). Falls back to system/tree when uri is absent or lacks the scheme, so the
// get path (uri = entity://<peer>/system/tree) and unrouted ops both scope-check the real
// handler namespace instead of a hardcoded one. Closes handler_scope_denied.
// Also sets g_target_peer_ptr/g_target_peer_len (§5.2 extract_peer, F-peers): the uri's first
// path segment when it validates as a real peer id (is_peer_id above), else the default —
// this peer's own g_peerid/g_peerid_len — exactly extract_peer's local-peer fallback. Every
// early-return path below leaves that default in place, matching extract_peer's short-form/
// no-scheme/no-slash cases (all of which mean "no peer prefix" -> local peer).
	.globl derive_handler
	.type derive_handler, %function
derive_handler:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]         // x19=cursor(rbx), x20=uri ptr(r12)
	stp  x21, x22, [sp, #32]         // x21=uri len/remaining(r13), x22=segment start(r14)
	adr_l x9, va_systree            // default handler = system/tree
	adr_l x10, g_handler_ptr
	str  x9, [x10]
	mov  x9, #11
	adr_l x10, g_handler_len
	str  x9, [x10]
	adr_l x9, g_peerid              // default target_peer = local peer id
	adr_l x10, g_target_peer_ptr
	str  x9, [x10]
	adr_l x9, g_peerid_len
	ldr  x9, [x9]
	adr_l x10, g_target_peer_len
	str  x9, [x10]
	// x0 = exec (preserved into map_find)
	adr_l x1, k_uri
	mov  x2, #3
	bl   map_find                   // x0 = exec (preserved)
	cbz  x0, .Ldh_ret
	bl   get_text                   // x0 = uri ptr, x2 = uri len
	mov  x20, x0
	mov  x21, x2
	cmp  x21, #9                    // "entity://" = 9 bytes
	b.lo .Ldh_ret
	mov  x0, x20
	adr_l x1, s_entity_scheme
	mov  x2, #9
	bl   memeq
	cbz  x0, .Ldh_ret
	add  x19, x20, #9               // cursor past the scheme
	mov  x22, x19                   // first-segment start (candidate target_peer)
	sub  x21, x21, #9              // remaining len (the "<peer>/<handler>" authority+path)
.Ldh_scan:
	cbz  x21, .Ldh_ret              // no '/', keep defaults (handler + target_peer)
	ldrb w9, [x19]
	cmp  w9, #0x2f
	b.eq .Ldh_found
	add  x19, x19, #1
	sub  x21, x21, #1
	b    .Ldh_scan
.Ldh_found:
	// candidate peer-id segment = [x22, x19) — validate before adopting it as target_peer
	// (extract_peer only trusts a first segment that is_peer_id).
	sub  x1, x19, x22               // segment length
	mov  x0, x22
	bl   is_peer_id
	cbz  x0, .Ldh_not_peer
	adr_l x9, g_target_peer_ptr
	str  x22, [x9]
	sub  x9, x19, x22
	adr_l x10, g_target_peer_len
	str  x9, [x10]
.Ldh_not_peer:
	add  x19, x19, #1               // skip the '/'
	sub  x21, x21, #1
	adr_l x9, g_handler_ptr
	str  x19, [x9]
	adr_l x9, g_handler_len
	str  x21, [x9]
.Ldh_ret:
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret
// =====================================================================
// verify_get_scope(x0 = exec data map) -> x0 = 0 authorized, 1 rejected (403 sent).
// §5.2 grant-scope stage, after verify_get_cap: the presented token must carry a grant that
// permits (operation, handler [from uri], resource-target). No matching grant → 403
// capability_denied (default-deny).
	.type verify_get_scope, %function
// x23=exec, x19=cap hash, x22=token data map, x21=now.
verify_get_scope:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x23, x0                     // exec
	// derive the request's handler namespace from data.uri (→ g_handler_ptr/len).
	mov  x0, x23                     // exec
	bl   derive_handler
	// capability → token → token data map
	mov  x0, x23
	adr_l x1, k_capability
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvgsc_ok               // (verify_get_cap already enforced presence)
	bl   get_text
	mov  x19, x0                     // cap hash
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvgsc_ok
	mov  x1, x19
	bl   included_find_by_key
	cbz  x0, .Lvgsc_ok
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvgsc_ok
	mov  x22, x0                     // token data map
	// ---- §5.5a frame for the DISPATCH surface: the presented cap's own granter ----
	// Derived here rather than assumed to be the local peer — they are byte-identical for
	// every self-issued capability, which is exactly why framing against the verifier stays
	// latent until a foreign-granted cap arrives.
	mov  x0, x22
	adr_l x1, ka_granter
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lvgsc_403
	mov  x20, x0
	bl   read_head                   // x1 = major type
	cmp  x1, #5
	b.ne .Lvgsc_single_frame
	// §3.6 K-of-N root: there is no single granter, so §5.5a has no granter peer_id to frame
	// against. The local peer is the CORRECT frame here and not a fallback — M6 already
	// required that the local peer be in the signer set AND have signed, and §5.5 says a
	// quorum cap's "subsequent use is locally rooted". The quorum authorized issuance; the
	// namespace its patterns name is this peer's.
	adr_l x0, g_dfr
	adr_l x1, g_peerid
	adr_l x9, g_peerid_len
	ldr  x2, [x9]
	adr_l x9, g_dfrlen
	str  x2, [x9]
	bl   mcpy
	b    .Lvgsc_frame_ok
.Lvgsc_single_frame:
	mov  x0, x20
	bl   get_text
	mov  x20, x0                     // granter hash
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvgsc_403
	mov  x1, x20
	adr_l x2, g_dfr
	adr_l x3, g_dfrlen
	bl   peerid_of
	cbz  x0, .Lvgsc_403
.Lvgsc_frame_ok:
	// ---- token temporal validity (only fires if the fields are present) ----
	bl   now_ms                      // x0 = wall-clock ms
	mov  x21, x0                     // now
	// expires_at present and now > it → expired
	mov  x0, x22
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvgsc_nb
	bl   read_head                   // x2 = expires_at (uint ms)
	cmp  x21, x2
	b.hi .Lvgsc_403                  // now > expires_at
.Lvgsc_nb:
	// not_before present and now < it → not yet valid
	mov  x0, x22
	adr_l x1, ka_notbefore
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvgsc_temporal_ok
	bl   read_head                   // x2 = not_before (uint ms)
	cmp  x21, x2
	b.lo .Lvgsc_403                  // now < not_before
.Lvgsc_temporal_ok:
	// operation
	mov  x0, x23
	adr_l x1, k_op
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lvgsc_403
	bl   get_text
	mov  x20, x0                     // op ptr
	mov  x19, x2                     // op len
	// target = resource.targets[0]
	mov  x0, x23
	adr_l x1, k_resource
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvgsc_403
	adr_l x1, k_targets
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lvgsc_403
	bl   read_head                   // array head: x2=count
	cbz  x2, .Lvgsc_403
	bl   get_text                    // x0=target ptr, x2=target len
	// grant_scope_ok(token_data, target ptr, target len, op ptr, op len)
	mov  x1, x0                      // target ptr
	mov  x0, x22                     // token data
	// x2 already = target len
	mov  x3, x20                     // op ptr
	mov  x4, x19                     // op len
	bl   grant_scope_ok
	cbnz x0, .Lvgsc_ok
.Lvgsc_403:
	mov  x0, #403
	adr_l x1, ec_cap_denied
	bl   send_error
	mov  x0, #1
	b    .Lvgsc_ret
.Lvgsc_ok:
	mov  x0, #0
.Lvgsc_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// =====================================================================
// grant_scope_ok(x0=token data map, x1=target ptr, x2=target len, x3=op ptr, x4=op len)
//   -> x0 = 1 if some grant permits (operation ∈ operations.include) ∧ (handler ∈
//      handlers.include) ∧ (target matches resources.include), else 0. "*" wildcards honored.
// The handler is g_handler_ptr/len, parsed from data.uri by derive_handler.
	.globl grant_scope_ok
	.type grant_scope_ok, %function
// x22=target ptr, x23=target len, x24 is the global cursor (untouched), x25=op ptr,
// x26=op len, x21=cursor(grant map ptr), x19=grant count. (r12→x20, r13→x22, r14→x23,
// r15→x25, rbp→x26, rbx→x19 — chosen to avoid the x24 writer cursor.)
grant_scope_ok:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	str  x26, [sp, #64]
	mov  x22, x1                     // target ptr
	mov  x23, x2                     // target len
	mov  x25, x3                     // op ptr
	mov  x26, x4                     // op len
	// grants = map_find(token_data, "grants", 6)
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find                    // x0 = token data (still) map_find(x0,...)
	cbz  x0, .Lgs_no
	bl   read_head                   // x0=first elem, x1=4, x2=count
	mov  x20, x0                     // cursor (grant map ptr)
	mov  x19, x2                     // grant count
.Lgs_loop:
	cbz  x19, .Lgs_no
	// operations.include ∋ op ?
	mov  x0, x20
	adr_l x1, ka_operations
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lgs_next
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lgs_next
	mov  x1, x25                     // op ptr
	mov  x2, x26                     // op len
	bl   array_contains_star
	cbz  x0, .Lgs_next
	// handlers.include ∋ system/tree ?
	mov  x0, x20
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lgs_next
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lgs_next
	adr_l x9, g_handler_ptr          // request handler (parsed from data.uri)
	ldr  x1, [x9]
	adr_l x9, g_handler_len
	ldr  x2, [x9]
	bl   array_contains_star
	cbz  x0, .Lgs_next
	// peers.include ∋ target_peer ? (§5.2/F-peers) grant.peers defaults to
	// {include:[local_peer_id]} when the grant omits the field entirely.
	mov  x0, x20
	adr_l x1, ka_peers
	mov  x2, #5
	bl   map_find
	cbz  x0, .Lgs_peers_default
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lgs_peers_default
	adr_l x9, g_target_peer_ptr
	ldr  x1, [x9]
	adr_l x9, g_target_peer_len
	ldr  x2, [x9]
	bl   array_contains_star
	cbz  x0, .Lgs_next
	b    .Lgs_peers_ok
.Lgs_peers_default:
	adr_l x9, g_target_peer_len
	ldr  x10, [x9]                   // target_peer len
	adr_l x9, g_peerid_len
	ldr  x9, [x9]                    // local peer id len
	cmp  x10, x9
	b.ne .Lgs_next
	adr_l x0, g_target_peer_ptr
	ldr  x0, [x0]                    // target_peer ptr
	adr_l x1, g_peerid               // local peer id ptr (inline buffer, not a pointer slot)
	mov  x2, x9                      // len (shared)
	bl   memeq
	cbz  x0, .Lgs_next
.Lgs_peers_ok:
	// resources.include matches target ?
	mov  x0, x20
	adr_l x1, ka_resources
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lgs_next
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lgs_next
	mov  x1, x22                     // target ptr
	mov  x2, x23                     // target len
	bl   resources_cover_target
	cbnz x0, .Lgs_yes
.Lgs_next:
	mov  x0, x20
	bl   skip_value                  // advance past this grant map
	mov  x20, x0
	sub  x19, x19, #1
	b    .Lgs_loop
.Lgs_yes:
	mov  x0, #1
	b    .Lgs_ret
.Lgs_no:
	mov  x0, #0
.Lgs_ret:
	ldr  x26, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// op_scope_ok(x0 = token data, x1 = op ptr, x2 = op len) -> x0 = 1 if some grant permits
// (operation ∈ operations.include) ∧ (handler ∈ handlers.include) ∧ (target peer ∈ peers).
// The RESOURCE dimension is absent by construction: these are the capability-vocabulary ops
// that carry no resource.targets, so there is no target to match and asking for one would
// deny every one of them.
	.type op_scope_ok, %function
op_scope_ok:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x22, x1                     // op ptr
	mov  x23, x2                     // op len
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find
	cbz  x0, .Los_no
	bl   read_head
	cmp  x1, #4
	b.ne .Los_no
	mov  x20, x0                     // grant cursor
	mov  x19, x2                     // grant count
.Los_loop:
	cbz  x19, .Los_no
	mov  x0, x20
	adr_l x1, ka_operations
	mov  x2, #10
	bl   get_include
	cbz  x0, .Los_next
	mov  x1, x22
	mov  x2, x23
	bl   array_contains_star
	cbz  x0, .Los_next
	mov  x0, x20
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   get_include
	cbz  x0, .Los_next
	adr_l x9, g_handler_ptr
	ldr  x1, [x9]
	adr_l x9, g_handler_len
	ldr  x2, [x9]
	bl   array_contains_star
	cbz  x0, .Los_next
	mov  x0, x20
	adr_l x1, ka_peers
	mov  x2, #5
	bl   get_include
	cbz  x0, .Los_peers_default
	adr_l x9, g_target_peer_ptr
	ldr  x1, [x9]
	adr_l x9, g_target_peer_len
	ldr  x2, [x9]
	bl   array_contains_star
	cbz  x0, .Los_next
	b    .Los_yes
.Los_peers_default:
	adr_l x9, g_target_peer_len
	ldr  x10, [x9]
	adr_l x9, g_peerid_len
	ldr  x9, [x9]
	cmp  x10, x9
	b.ne .Los_next
	adr_l x0, g_target_peer_ptr
	ldr  x0, [x0]
	adr_l x1, g_peerid
	mov  x2, x9
	bl   memeq
	cbz  x0, .Los_next
	b    .Los_yes
.Los_next:
	mov  x0, x20
	bl   skip_value
	mov  x20, x0
	sub  x19, x19, #1
	b    .Los_loop
.Los_yes:
	mov  x0, #1
	b    .Los_ret
.Los_no:
	mov  x0, #0
.Los_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// verify_op_scope(x0 = exec data map) -> x0 = 0 authorized, 1 rejected (403 sent).
// §5.2 operation-scope gate for a capability-vocabulary op with no resource.targets. Without
// it a peer that authenticates a caller then routes straight into the handler never asks
// whether the presented capability covers this op on this handler at all — and a floor cap
// (capability:request only) would reach configure/revoke unchecked.
	.type verify_op_scope, %function
verify_op_scope:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x23, x0                     // exec
	bl   derive_handler              // x0 = exec (→ g_handler_ptr/len, g_target_peer_*)
	mov  x0, x23
	adr_l x1, k_capability
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvos_403
	bl   get_text
	mov  x19, x0                     // cap hash
	adr_l x0, b_req
	adr_l x1, ka_included
	mov  x2, #8
	bl   map_find
	cbz  x0, .Lvos_403
	mov  x1, x19
	bl   included_find_by_key
	cbz  x0, .Lvos_403
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lvos_403
	mov  x22, x0                     // token data
	bl   now_ms
	mov  x21, x0                     // now
	mov  x0, x22
	adr_l x1, ka_expires
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvos_nb
	bl   read_head
	cmp  x21, x2
	b.hi .Lvos_403                   // now > expires_at
.Lvos_nb:
	mov  x0, x22
	adr_l x1, ka_notbefore
	mov  x2, #10
	bl   map_find
	cbz  x0, .Lvos_op
	bl   read_head
	cmp  x21, x2
	b.lo .Lvos_403                   // now < not_before
.Lvos_op:
	mov  x0, x23
	adr_l x1, k_op
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lvos_403
	bl   get_text
	mov  x1, x0                      // op ptr
	mov  x0, x22                     // token data
	// x2 already = op len
	bl   op_scope_ok
	cbnz x0, .Lvos_ok
.Lvos_403:
	mov  x0, #403
	adr_l x1, ec_cap_denied
	bl   send_error
	mov  x0, #1
	b    .Lvos_ret
.Lvos_ok:
	mov  x0, #0
.Lvos_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// resources_cover_target(x0 = resources.include array, x1 = target ptr, x2 = target len)
//   -> x0 = 1 if some pattern covers the request target under §5.5a.
//
// §5.5a surface 1, the DISPATCH boundary. The two sides canonicalize against DIFFERENT
// frames, and that asymmetry is the rule: a cap's resource patterns are the GRANTER's to
// write, so they canonicalize against the granter's peer_id (g_dfr, derived in
// verify_get_scope); the request target is a path into THIS peer's namespace, so it
// canonicalizes against the local peer_id. Frame both against the local peer and a
// foreign-granted bare "*" silently becomes "/{verifier}/*" and authorizes the verifier's
// own namespace — which is what captok_form_dispatch_minted_pl_presented_xpeer exists to
// catch, and which stays invisible for as long as the peer refuses foreign-granted caps
// outright (a vacuous pass that the chain walk converts into a real one).
	.type resources_cover_target, %function
resources_cover_target:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	stp  x26, x27, [sp, #64]
	mov  x19, x0                     // include array
	mov  x0, x1
	mov  x1, x2
	adr_l x2, g_peerid
	adr_l x9, g_peerid_len
	ldr  x3, [x9]
	adr_l x4, b_canon_a
	bl   canon
	mov  x20, x0                     // canonical target length
	mov  x0, x19
	bl   read_head
	cmp  x1, #4
	b.ne .Lrct_no
	mov  x21, x0                     // pattern cursor
	mov  x22, x2                     // remaining
.Lrct_loop:
	cbz  x22, .Lrct_no
	mov  x0, x21
	bl   read_head                   // x0 = pattern bytes, x2 = len
	mov  x23, x0
	mov  x25, x2
	add  x21, x0, x2
	sub  x22, x22, #1
	mov  x0, x23
	mov  x1, x25
	adr_l x2, g_dfr
	adr_l x9, g_dfrlen
	ldr  x3, [x9]
	adr_l x4, b_canon_b
	bl   canon
	mov  x3, x0
	adr_l x0, b_canon_a
	mov  x1, x20
	adr_l x2, b_canon_b
	bl   pat_covers
	cbz  x0, .Lrct_loop
	mov  x0, #1
	b    .Lrct_ret
.Lrct_no:
	mov  x0, #0
.Lrct_ret:
	ldp  x26, x27, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #96
	ret

// array_contains_star(x0=array, x1=needle, x2=needle len) -> x0 = 1 if the array
// contains the needle OR a bare "*". Reuses array_contains twice.
	.type array_contains_star, %function
// x20=array, x21=needle, x22=needle len.
array_contains_star:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	mov  x20, x0                     // array
	mov  x21, x1                     // needle
	mov  x22, x2                     // needle len
	bl   array_contains              // (x0=array, x1=needle, x2=len)
	cbnz x0, .Lacs_yes
	mov  x0, x20
	adr_l x1, s_star
	mov  x2, #1
	bl   array_contains
	cbnz x0, .Lacs_yes
	mov  x0, #0
	b    .Lacs_ret
.Lacs_yes:
	mov  x0, #1
.Lacs_ret:
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// resource_matches(x0=include array, x1=target ptr, x2=target len) -> x0 = 1 if any
// pattern matches. Patterns: bare "*" (any); trailing "/*" (prefix match on everything up to
// and including the slash); otherwise an exact match.
	.type resource_matches, %function
// x22=target ptr, x23=target len, x20=cursor, x19=pattern count, x25=pattern ptr,
// x26=pattern len.
resource_matches:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	str  x26, [sp, #64]
	mov  x22, x1                     // target ptr
	mov  x23, x2                     // target len
	bl   read_head                   // x0=array → x0=first elem, x2=count
	mov  x20, x0                     // cursor
	mov  x19, x2                     // pattern count
.Lrm_l:
	cbz  x19, .Lrm_no
	mov  x0, x20
	bl   read_head                   // pattern text: x0=ptr, x2=len
	mov  x25, x0                     // pattern ptr
	mov  x26, x2                     // pattern len
	add  x20, x0, x2                 // advance cursor past pattern
	sub  x19, x19, #1
	// case bare "*"
	cmp  x26, #1
	b.ne .Lrm_check_suffix
	ldrb w9, [x25]
	cmp  w9, #0x2a
	b.eq .Lrm_yes
	b    .Lrm_l
.Lrm_check_suffix:
	// trailing "/*" ? (plen>=2 and last two bytes are '/','*')
	cmp  x26, #2
	b.lo .Lrm_exact
	add  x10, x25, x26
	ldrb w9, [x10, #-1]              // pattern[plen-1]
	cmp  w9, #0x2a
	b.ne .Lrm_exact
	ldrb w9, [x10, #-2]             // pattern[plen-2]
	cmp  w9, #0x2f
	b.ne .Lrm_exact
	// prefix = pattern[0 .. plen-1] (through the slash, i.e. plen-1 bytes); target must be
	// at least that long and share the prefix bytes.
	sub  x9, x26, #1                 // prefix len (keep the '/')
	cmp  x23, x9
	b.lo .Lrm_l                      // target shorter than prefix → no match
	mov  x0, x25                     // pattern
	mov  x1, x22                     // target
	mov  x2, x9                      // prefix len → memeq len (x2)
	bl   memeq
	cbnz x0, .Lrm_yes
	b    .Lrm_l
.Lrm_exact:
	cmp  x23, x26
	b.ne .Lrm_l
	mov  x0, x25                     // pattern
	mov  x1, x22                     // target
	mov  x2, x26                     // len → x2
	bl   memeq
	cbnz x0, .Lrm_yes
	b    .Lrm_l
.Lrm_yes:
	mov  x0, #1
	b    .Lrm_ret
.Lrm_no:
	mov  x0, #0
.Lrm_ret:
	ldr  x26, [sp, #64]
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// get_include(x0 = grant map, x1 = field cstr, x2 = field len) -> x0 = <field>.include
// array value ptr | 0.  grant[field]["include"].
	.type get_include, %function
get_include:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	bl   map_find
	cbz  x0, .Lgi_no
	adr_l x1, ka_include
	mov  x2, #7
	bl   map_find
	cbz  x0, .Lgi_no
	ldp  x29, x30, [sp], #16
	ret
.Lgi_no:
	mov  x0, #0
	ldp  x29, x30, [sp], #16
	ret

// array_subset_star(x0 = req array value, x1 = caller array value) -> x0 = 1 if every
// text element of req appears in caller (a bare "*" in caller matches any element). An empty
// req array is a vacuous subset (1).
	.type array_subset_star, %function
// x25=caller array value, x20=cursor, x19=remaining count, x22=elem ptr, x23=elem len.
array_subset_star:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x22, x23, [sp, #32]
	str  x25, [sp, #48]
	mov  x25, x1                     // caller array value
	bl   read_head                   // x0 = req array → x0=first elem, x2=count
	mov  x20, x0                     // cursor
	mov  x19, x2                     // remaining count
.Lss_loop:
	cbz  x19, .Lss_yes
	mov  x0, x20
	bl   read_head                   // element text: x0=ptr, x2=len
	mov  x22, x0                     // elem ptr
	mov  x23, x2                     // elem len
	add  x20, x0, x2                 // advance cursor past this element
	sub  x19, x19, #1
	mov  x0, x25                     // caller array
	mov  x1, x22
	mov  x2, x23
	bl   array_contains_star
	cbnz x0, .Lss_loop               // covered → next req element
	mov  x0, #0                      // some element not covered → not a subset
	b    .Lss_ret
.Lss_yes:
	mov  x0, #1
.Lss_ret:
	ldr  x25, [sp, #48]
	ldp  x22, x23, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// resources_subset(x0 = req resources.include, x1 = caller resources.include) -> x0 = 1 if
// every req resource is matched by a caller pattern (resource_matches: "*", trailing "/*",
// exact). Empty req → 1.
	.type resources_subset, %function
// x25=caller resources array, x20=cursor, x19=count, x22=res ptr, x23=res len.
resources_subset:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x22, x23, [sp, #32]
	str  x25, [sp, #48]
	mov  x25, x1                     // caller resources array
	bl   read_head                   // x0 = req array → x0=first, x2=count
	mov  x20, x0
	mov  x19, x2
.Lrs_loop:
	cbz  x19, .Lrs_yes
	mov  x0, x20
	bl   read_head                   // req resource text: x0=ptr, x2=len
	mov  x22, x0
	mov  x23, x2
	add  x20, x0, x2
	sub  x19, x19, #1
	mov  x0, x25                     // caller resources array
	mov  x1, x22
	mov  x2, x23
	bl   resource_matches
	cbnz x0, .Lrs_loop
	mov  x0, #0
	b    .Lrs_ret
.Lrs_yes:
	mov  x0, #1
.Lrs_ret:
	ldr  x25, [sp, #48]
	ldp  x22, x23, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// grant_covers(x0 = caller grant map, x1 = req grant map) -> x0 = 1 if the caller grant
// authorizes everything the req grant asks for: req.operations ⊆ caller.operations,
// req.handlers ⊆ caller.handlers, req.resources all matched by caller.resources.
	.type grant_covers, %function
// x20=caller grant, x22=req grant, x19=req.<field> include (scratch across get_include).
grant_covers:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x22, [sp, #32]
	mov  x20, x0                     // caller grant
	mov  x22, x1                     // req grant
	// operations
	mov  x0, x22
	adr_l x1, ka_operations
	mov  x2, #10
	bl   get_include
	cbz  x0, .Lgc_no                 // req without operations.include → treat as uncoverable
	mov  x19, x0                     // req.ops
	mov  x0, x20
	adr_l x1, ka_operations
	mov  x2, #10
	bl   get_include
	cbz  x0, .Lgc_no
	mov  x1, x0                      // caller.ops
	mov  x0, x19                     // req.ops
	bl   array_subset_star
	cbz  x0, .Lgc_no
	// handlers
	mov  x0, x22
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   get_include
	cbz  x0, .Lgc_no
	mov  x19, x0
	mov  x0, x20
	adr_l x1, ka_handlers
	mov  x2, #8
	bl   get_include
	cbz  x0, .Lgc_no
	mov  x1, x0
	mov  x0, x19
	bl   array_subset_star
	cbz  x0, .Lgc_no
	// resources (req resources ⊆ caller resources by pattern match); absent req resources → ok
	mov  x0, x22
	adr_l x1, ka_resources
	mov  x2, #9
	bl   get_include
	cbz  x0, .Lgc_yes                // no resources requested → nothing to bound
	mov  x19, x0
	mov  x0, x20
	adr_l x1, ka_resources
	mov  x2, #9
	bl   get_include
	cbz  x0, .Lgc_no                 // req asks resources but caller grant has none
	mov  x1, x0
	mov  x0, x19
	bl   resources_subset
	cbz  x0, .Lgc_no
.Lgc_yes:
	mov  x0, #1
	b    .Lgc_ret
.Lgc_no:
	mov  x0, #0
.Lgc_ret:
	ldr  x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// grants_attenuated(x0 = requested grants array value, x1 = caller token data map) ->
// x0 = 1 if every requested grant is covered by some caller grant (i.e. the request does
// not widen scope beyond the caller's authority). Empty requested set → 1.
	.type grants_attenuated, %function
// x25=caller token data, x22=req cursor, x23=req count, x19=this requested grant map,
// x20=caller cursor, x21=caller count (saved/restored around the inner loop in place of the
// x86 push/pop %r14).
grants_attenuated:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x25, [sp, #48]
	mov  x25, x1                     // caller token data
	bl   read_head                   // x0 = req grants → x0=first, x2=count
	mov  x22, x0                     // req cursor
	mov  x23, x2                     // req count
.Lga_req:
	cbz  x23, .Lga_yes
	mov  x19, x22                    // this requested grant map
	// walk the caller grants, seeking one that covers this requested grant
	mov  x0, x25
	adr_l x1, ka_grants
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lga_no
	bl   read_head                   // caller grants → x0=first, x2=count
	mov  x20, x0                     // caller cursor
	mov  x21, x2                     // caller count (inner loop counter)
.Lga_caller:
	cbz  x21, .Lga_uncovered
	mov  x0, x20
	mov  x1, x19
	bl   grant_covers
	cbnz x0, .Lga_covered
	mov  x0, x20
	bl   skip_value
	mov  x20, x0
	sub  x21, x21, #1
	b    .Lga_caller
.Lga_uncovered:
	b    .Lga_no
.Lga_covered:
	// advance req cursor past this grant
	mov  x0, x22
	bl   skip_value
	mov  x22, x0
	sub  x23, x23, #1
	b    .Lga_req
.Lga_yes:
	mov  x0, #1
	b    .Lga_ret
.Lga_no:
	mov  x0, #0
.Lga_ret:
	ldp  x23, x25, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// included_find_by_key(x0 = included map, x1 = key33 ptr) -> x0 = value entity ptr | 0.
// `included` is keyed by 33-byte content hashes; returns the value whose key bytes match.
	.type included_find_by_key, %function
// x22=key, x20=cursor, x19=remaining pairs, x23=key bytes.
included_find_by_key:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x22, x23, [sp, #32]
	mov  x22, x1                     // key
	bl   read_head                   // x0=included → x0=after, x1=5, x2=count
	mov  x20, x0                     // cursor
	mov  x19, x2                     // remaining pairs
.Lifk_l:
	cbz  x19, .Lifk_no
	mov  x0, x20
	bl   read_head                   // key bstr: x0=bytes, x2=len
	mov  x23, x0                     // key bytes
	add  x20, x0, x2                 // cursor → value
	cmp  x2, #33
	b.ne .Lifk_skipval
	mov  x0, x23
	mov  x1, x22
	mov  x2, #33                     // memeq len (x2)
	bl   memeq
	cbnz x0, .Lifk_found
.Lifk_skipval:
	mov  x0, x20
	bl   skip_value                  // skip value entity
	mov  x20, x0
	sub  x19, x19, #1
	b    .Lifk_l
.Lifk_found:
	mov  x0, x20                     // value ptr (cursor sits at value)
	b    .Lifk_ret
.Lifk_no:
	mov  x0, #0
.Lifk_ret:
	ldp  x22, x23, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// find_req_sig(x0 = included map, x1 = author33, x2 = root_ch33) -> x0 = 64-byte
// signature ptr | 0. Scans `included` for a system/signature with signer==author and
// target==root_ch. (Pure reader — no FFI — so 16B alignment is irrelevant here.)
	.type find_req_sig, %function
// x22=author, x23=root_ch, x20=cursor, x19=remaining pairs, x25=value entity ptr,
// x26=sig data map.
find_req_sig:
	stp  x29, x30, [sp, #-80]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x22, x23, [sp, #32]
	stp  x25, x26, [sp, #48]
	mov  x22, x1                     // author
	mov  x23, x2                     // root_ch
	bl   read_head                   // x0=included → x0=after, x2=count
	mov  x20, x0                     // cursor
	mov  x19, x2                     // remaining pairs
.Lfrs_l:
	cbz  x19, .Lfrs_no
	mov  x0, x20
	bl   read_head                   // key bstr: x0=bytes, x2=len
	add  x25, x0, x2                 // value entity ptr
	mov  x0, x25
	bl   skip_value                  // advance cursor to next pair NOW
	mov  x20, x0
	sub  x19, x19, #1
	// value.type == "system/signature"?
	mov  x0, x25
	adr_l x1, k_type
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lfrs_l
	bl   get_text
	cmp  x2, #16
	b.ne .Lfrs_l
	mov  x1, x0
	adr_l x0, ta_sig
	mov  x2, #16                     // memeq len (x2)
	bl   memeq
	cbz  x0, .Lfrs_l
	// data map
	mov  x0, x25
	adr_l x1, k_data
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lfrs_l
	mov  x26, x0                     // sig data map
	// signer == author?
	mov  x0, x26
	adr_l x1, ka_signer
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lfrs_l
	bl   get_text
	cmp  x2, #33
	b.ne .Lfrs_l
	mov  x1, x0
	mov  x0, x22                     // author
	mov  x2, #33                     // memeq len (x2)
	bl   memeq
	cbz  x0, .Lfrs_l
	// target == root_ch?
	mov  x0, x26
	adr_l x1, ka_target
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lfrs_l
	bl   get_text
	cmp  x2, #33
	b.ne .Lfrs_l
	mov  x1, x0
	mov  x0, x23                     // root_ch
	mov  x2, #33                     // memeq len (x2)
	bl   memeq
	cbz  x0, .Lfrs_l
	// match → return signature bytes (64)
	mov  x0, x26
	adr_l x1, ka_sig
	mov  x2, #9
	bl   map_find
	cbz  x0, .Lfrs_l
	bl   get_text                    // x0 = sig ptr, x2 = 64
	b    .Lfrs_ret
.Lfrs_no:
	mov  x0, #0
.Lfrs_ret:
	ldp  x25, x26, [sp, #48]
	ldp  x22, x23, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #80
	ret

// mcmp33(x0=a, x1=b) -> x0 = a[i]-b[i] at first differing byte over 33 bytes (0 if equal).
// Sign gives bytewise order. Clobbers only x0, x9, x10, x11. Leaf. (x0/x1 stay the pointers;
// the a-byte lands in w9 so x0 — base + return — is not stomped mid-loop.)
	.type mcmp33, %function
mcmp33:
	mov  w10, #0                     // i
.Lmc_l:
	cmp  w10, #33
	b.hs .Lmc_eq
	ldrb w9, [x0, w10, uxtw]
	ldrb w11, [x1, w10, uxtw]
	subs w9, w9, w11
	b.ne .Lmc_diff
	add  w10, w10, #1
	b    .Lmc_l
.Lmc_diff:
	mov  w0, w9
	ret
.Lmc_eq:
	mov  x0, #0
	ret

// find_sig_entity(x0=included map ptr) -> x0 = the system/signature entity ptr | 0
	.type find_sig_entity, %function
// x20=cursor, x19=count, x22=value entity ptr.
find_sig_entity:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x22, [sp, #32]
	bl   read_head                   // x0=cursor, x2=count
	mov  x20, x0
	mov  x19, x2
.Lfse_loop:
	cbz  x19, .Lfse_none
	mov  x0, x20
	bl   skip_value                  // skip key (33-byte hash)
	mov  x20, x0
	mov  x22, x20                    // value entity ptr
	mov  x0, x22
	adr_l x1, k_type
	mov  x2, #4
	bl   map_find
	cbz  x0, .Lfse_skipval
	bl   get_text
	cmp  x2, #16
	b.ne .Lfse_skipval
	mov  x1, x0
	adr_l x0, ta_sig
	mov  x2, #16                     // memeq len (x2)
	bl   memeq
	cbnz x0, .Lfse_found
.Lfse_skipval:
	mov  x0, x22
	bl   skip_value
	mov  x20, x0
	sub  x19, x19, #1
	b    .Lfse_loop
.Lfse_found:
	mov  x0, x22
	b    .Lfse_ret
.Lfse_none:
	mov  x0, #0
.Lfse_ret:
	ldr  x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// build_echo_response(x0 = exec data map) — system/validate/echo: return the params
// entity verbatim as the result (the §6.11(b) request_id round-trip probe).
	.type build_echo_response, %function
// x20=params entity ptr, x22=params entity byte length, x24=writer cursor (was x86 r15),
// x23=env length. x24 is the GLOBAL cursor; here we set it up (mirrors x86 lea …,%r15).
build_echo_response:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x22, x23, [sp, #32]
	str  x24, [sp, #48]
	// params entity ptr + byte length
	adr_l x1, ka_params
	mov  x2, #6
	bl   map_find
	cbz  x0, .Lecho_ret
	mov  x20, x0                     // params entity ptr
	bl   skip_value
	sub  x0, x0, x20
	mov  x22, x0                     // params entity byte length
	// resp data {result: <params entity raw>, status:200, request_id}
	adr_l x24, b_ar_resp
	mov  x1, #3
	bl   w_map
	adr_l x0, k_result
	bl   w_cstr
	mov  x1, x20                     // params ptr
	mov  x2, x22                     // params len
	bl   w_raw                       // embed the params entity verbatim
	adr_l x0, k_status
	bl   w_cstr
	mov  x1, #200
	bl   w_uint
	adr_l x0, k_rid
	bl   w_cstr
	adr_l x9, g_rid_ptr
	ldr  x1, [x9]
	adr_l x9, g_rid_len
	ldr  x2, [x9]
	bl   w_txt
	adr_l x0, b_ar_resp
	sub  x2, x24, x0                 // resp data length
	adr_l x9, g_ardlen
	str  x2, [x9]
	adr_l x0, t_resp
	mov  x1, #32
	adr_l x2, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x3, [x9]
	adr_l x4, resp_ch2
	bl   ec_content_hash
	// envelope {root: resp}
	adr_l x24, b_ar_env
	mov  x1, #1
	bl   w_map
	adr_l x0, k_root
	bl   w_cstr
	adr_l x0, t_resp
	adr_l x1, b_ar_resp
	adr_l x9, g_ardlen
	ldr  x2, [x9]
	adr_l x3, resp_ch2
	bl   w_entity
	adr_l x0, b_ar_env
	sub  x23, x24, x0                // env length
	rev  w9, w23                     // big-endian 4-byte length prefix
	adr_l x10, b_hdr
	str  w9, [x10]
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_hdr
	mov  x2, #4
	bl   write_all
	adr_l x9, g_connfd
	ldr  x0, [x9]
	adr_l x1, b_ar_env
	mov  x2, x23                     // env length
	bl   write_all
.Lecho_ret:
	ldr  x24, [sp, #48]
	ldp  x22, x23, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

	.section .note.GNU-stack,"",%progbits
