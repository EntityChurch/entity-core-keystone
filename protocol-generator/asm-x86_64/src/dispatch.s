# dispatch.s — frame read loop + envelope parse + routing + handlers.
# GAS/AT&T. Entities/hashes via FFI; the envelope/data-map CBOR via cbor.s (A-ASM-004).
# Currently implements: hello. authenticate/tree/capability/§9.1 floor land next.

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
# is_peer_id always scans exactly 58 entries.
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
	push %r15
	lea  b_peerdata(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  ka_ktype(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_pubkey(%rip), %rdi
	call w_cstr
	lea  g_pubkey(%rip), %rsi
	mov  $32, %rdx
	call w_bstr
	lea  b_peerdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_peerdata_len(%rip)
	lea  ta_peer(%rip), %rdi
	mov  $11, %rsi
	lea  b_peerdata(%rip), %rdx
	mov  g_peerdata_len(%rip), %rcx
	lea  g_identity_hash(%rip), %r8
	call ec_content_hash
	pop  %r15
	ret

# =====================================================================
# conn_serve(rdi = connfd) — read framed requests, dispatch each, until EOF.
# =====================================================================
	.globl conn_serve
	.type conn_serve, @function
conn_serve:
	push %r12
	mov  %rdi, %r12
	mov  %r12, g_connfd(%rip)
	call seed_dispatch_entities      # publish §6.2 native dispatch entities into this fork
.Lcs_loop:
	# read 4-byte BE length header
	mov  %r12, %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call read_full
	cmp  $4, %rax
	jne  .Lcs_done
	mov  b_hdr(%rip), %eax
	bswap %eax                       # BE → host
	mov  %eax, %ecx                  # frame len
	test %ecx, %ecx
	jz   .Lcs_loop                   # zero-length frame: ignore
	cmp  $0x1000000, %ecx            # > 16 MiB (§9.1 default payload cap) → 413, keep serving
	ja   .Lcs_oversize
	# read body
	mov  %r12, %rdi
	lea  b_req(%rip), %rsi
	mov  %ecx, %edx
	mov  %rdx, %r13
	call read_full
	cmp  %r13, %rax
	jne  .Lcs_done
	call dispatch
	jmp  .Lcs_loop
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
	# Measured 2026-08-29: the oracle timed out reading the response every time and
	# recorded "connection terminated without a 413 frame".
	#
	# Staying framed is worth nothing once the frame is known to be unservable, and
	# the connection is the attacker's to waste, not ours.
	movq $0, g_rid_len(%rip)
	mov  $413, %rdi
	lea  ec_payload_too_large(%rip), %rsi
	call send_error
	jmp  .Lcs_done
.Lcs_done:
	mov  %r12, %rdi
	ksys SYS_close
	pop  %r12
	ret

# read_full(rdi=fd, rsi=buf, rdx=n) -> rax = bytes read (n on success)
	.type read_full, @function
read_full:
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # fd
	mov  %rsi, %r13                  # buf
	mov  %rdx, %r14                  # remaining
	xor  %r15, %r15                  # got
.Lrf:	test %r14, %r14
	jz   .Lrf_done
	mov  %r12, %rdi
	lea  (%r13,%r15), %rsi
	mov  %r14, %rdx
	ksys SYS_read
	test %rax, %rax
	jle  .Lrf_done                   # EOF/error
	add  %rax, %r15
	sub  %rax, %r14
	jmp  .Lrf
.Lrf_done:
	mov  %r15, %rax
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	ret

# =====================================================================
# dispatch — parse b_req envelope, route by operation. (only hello for now)
# =====================================================================
	.type dispatch, @function
dispatch:
	push %rbx
	# root = map_find(b_req, "root")
	lea  b_req(%rip), %rdi
	lea  k_root(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_ret
	mov  %rax, g_root_ptr(%rip)
	# §7a: a root of type system/protocol/execute/response is a reply to one of our outbound
	# reentry echoes — demux it to its pending dispatch-outbound instead of dispatching.
	mov  %rax, %rdi
	lea  k_type(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_notresp
	mov  %rax, %rdi
	call get_text
	cmp  $32, %rdx
	jne  .Ld_notresp
	mov  %rax, %rdi
	lea  t_resp(%rip), %rsi
	mov  $32, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_notresp
	mov  g_root_ptr(%rip), %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_ret
	mov  %rax, %rdi
	call handle_dispatch_response
	jmp  .Ld_ret
.Ld_notresp:
	# exec = map_find(root, "data")
	mov  g_root_ptr(%rip), %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_ret
	mov  %rax, %rbx                  # rbx = exec data map
	# request_id → save
	mov  %rbx, %rdi
	lea  k_rid(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_ret
	mov  %rax, %rdi
	call get_text                    # rax=ptr, rdx=len
	mov  %rax, g_rid_ptr(%rip)
	mov  %rdx, g_rid_len(%rip)
	# operation
	mov  %rbx, %rdi
	lea  k_op(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Ld_ret
	mov  %rax, %rdi
	call get_text                    # rax=opptr, rdx=oplen
	# route: save op (ptr in rax, len in rdx) then compare.
	#
	# Every branch below dispatches on LENGTH first and only then compares bytes, so a
	# length collision with an op we do route is the case to get right: a byte mismatch
	# must fall through to .Ld_unknown (→ 501 unsupported_operation), never to .Ld_ret.
	# Falling to .Ld_ret answers NOTHING, and §4.9(c) deliver-or-signal makes that the
	# one outcome a peer may not produce — the caller cannot tell it from a dead peer and
	# waits out its own timeout. Measured 2026-08-30: `ping` collides with `echo` at
	# length 4 and was dropped on exactly this branch. It costs the caller a full 20 s
	# read deadline EVERY connection, which is why t2_2_connection_churn consumed the
	# entire 10-minute budget across 29 of its 100 cycles and starved nine categories —
	# a §4.9(c) violation presenting as a connection-pressure failure.
	mov  %rax, %r8                   # op ptr
	mov  %rdx, %r9                   # op len
	# op == "hello"?
	cmp  $5, %r9
	jne  .Ld_try_auth
	mov  %r8, %rdi
	lea  v_hello(%rip), %rsi
	mov  $5, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown                 # len 5 but not "hello" → 501, never a silent drop
	# §4.5 negotiation: reject a hello whose advertised hash_formats/key_types are
	# disjoint from ours (400) before building the happy-path response.
	mov  %rbx, %rdi                  # exec data map
	call check_hello_negotiation
	test %rax, %rax
	jnz  .Ld_ret                     # rejected (400 already sent)
	call build_hello_response
	jmp  .Ld_ret
.Ld_try_auth:
	# op == "authenticate"?
	cmp  $12, %r9
	jne  .Ld_try_echo
	mov  %r8, %rdi
	lea  va_authenticate(%rip), %rsi
	mov  $12, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown                 # len 12 but not "authenticate" → 501
	mov  %rbx, %rdi                  # exec data map ptr
	call build_authenticate_response
	jmp  .Ld_ret
.Ld_try_echo:
	# op == "echo"? (system/validate/echo)
	cmp  $4, %r9
	jne  .Ld_try_get
	mov  %r8, %rdi
	lea  va_echo(%rip), %rsi
	mov  $4, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown                 # len 4 but not "echo" — e.g. "ping" — → 501
	mov  %rbx, %rdi
	call build_echo_response
	jmp  .Ld_ret
.Ld_try_get:
	# op == "get"? (system/tree get) — resolve against the store + embedded read-only store.
	cmp  $3, %r9
	jne  .Ld_try_request
	mov  %r8, %rdi
	lea  va_get(%rip), %rsi
	mov  $3, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_try_put                 # len 3 but not "get" → maybe "put"
	mov  %rbx, %rdi                  # exec data map ptr
	call serve_tree_get
	jmp  .Ld_ret
.Ld_try_put:
	# op == "put"? (system/tree put) — write into the per-fork store (A-ASM-011).
	cmp  $3, %r9
	jne  .Ld_try_request
	mov  %r8, %rdi
	lea  va_put(%rip), %rsi
	mov  $3, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_try_request
	mov  %rbx, %rdi                  # exec data map ptr
	call serve_tree_put
	jmp  .Ld_ret
.Ld_try_request:
	# op == "request"? (system/capability request) — mint a token per params.data.grants.
	cmp  $7, %r9
	jne  .Ld_try_register
	mov  %r8, %rdi
	lea  va_request(%rip), %rsi
	mov  $7, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_try_register
	mov  %rbx, %rdi                  # exec data map ptr
	call build_request_response
	jmp  .Ld_ret
.Ld_try_register:
	# op == "register"? (system/handler register) — write handler entities to the store.
	cmp  $8, %r9
	jne  .Ld_try_unregister
	mov  %r8, %rdi
	lea  va_register(%rip), %rsi
	mov  $8, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_try_delegate
	mov  %rbx, %rdi
	call serve_register
	jmp  .Ld_ret
.Ld_try_delegate:
	# op == "delegate"? (system/capability delegate) — same-peer-only; unsupported in v1.
	mov  %r8, %rdi
	lea  va_delegate(%rip), %rsi
	mov  $8, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_try_dispatch
	mov  %rbx, %rdi
	call serve_delegate
	jmp  .Ld_ret
.Ld_try_dispatch:
	# op == "dispatch"? (§7a system/validate/dispatch-outbound) — originate a reentry echo.
	mov  %r8, %rdi
	lea  va_dispatch(%rip), %rsi
	mov  $8, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown
	mov  %rbx, %rdi
	call serve_dispatch_outbound
	jmp  .Ld_ret
.Ld_try_unregister:
	# op == "unregister"? (system/handler unregister) — remove handler entities.
	cmp  $10, %r9
	jne  .Ld_try_configure
	mov  %r8, %rdi
	lea  va_unregister(%rip), %rsi
	mov  $10, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown
	mov  %rbx, %rdi
	call serve_unregister
	jmp  .Ld_ret
.Ld_try_configure:
	# op == "configure"? (system/capability configure) — write a peer policy-entry.
	cmp  $9, %r9
	jne  .Ld_try_revoke
	mov  %r8, %rdi
	lea  va_configure(%rip), %rsi
	mov  $9, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown
	mov  %rbx, %rdi
	call serve_configure
	jmp  .Ld_ret
.Ld_try_revoke:
	# op == "revoke"? (system/capability revoke) — write a revocation marker.
	cmp  $6, %r9
	jne  .Ld_unknown
	mov  %r8, %rdi
	lea  va_revoke(%rip), %rsi
	mov  $6, %rcx
	call memeq
	test %rax, %rax
	jz   .Ld_unknown
	mov  %rbx, %rdi
	call serve_revoke
	jmp  .Ld_ret
.Ld_unknown:
	# An operation this peer doesn't route falls into two classes:
	#  - a KNOWN vocabulary op (delegate/configure/revoke/register/unregister/put) we don't
	#    (yet) implement gets an authorization decision — if the presented capability doesn't
	#    cover it, that's a 403 denial (verify_get_scope); otherwise it falls through to 501.
	#  - a genuinely UNKNOWN op → 501 unsupported_operation up front.
	# (A silent no-reply would block validate-peer ~20s/probe, so we always answer.)
	mov  %r8, %rdi                   # op ptr
	mov  %r9, %rsi                   # op len
	call op_is_known
	test %rax, %rax
	jz   .Ld_501                     # unknown op → 501
	mov  %rbx, %rdi                  # exec data map
	call verify_get_scope
	test %rax, %rax
	jnz  .Ld_ret                     # 403 already sent
.Ld_501:
	mov  $501, %rdi
	lea  ec_unsupported_op(%rip), %rsi
	call send_error
.Ld_ret:
	pop  %rbx
	ret

# op_is_known(rdi = op ptr, rsi = op len) -> rax = 1 if op is a known capability/handler/tree
# write op we recognise but don't route to a dedicated handler (delegate/configure/revoke/
# register/unregister/put). Such ops get an authorization decision (403); anything else is
# a genuinely unknown operation (501 unsupported_operation).
	.type op_is_known, @function
op_is_known:
	push %rbx
	push %r13
	push %r14                        # 3 (odd)
	mov  %rdi, %r13                  # op ptr
	mov  %rsi, %r14                  # op len
	cmp  $8, %r14
	jne  .Loik_c9
	mov  %r13, %rdi
	lea  va_delegate(%rip), %rsi
	mov  $8, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
	mov  %r13, %rdi
	lea  va_register(%rip), %rsi
	mov  $8, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
	jmp  .Loik_no
.Loik_c9:
	cmp  $9, %r14
	jne  .Loik_c6
	mov  %r13, %rdi
	lea  va_configure(%rip), %rsi
	mov  $9, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
	jmp  .Loik_no
.Loik_c6:
	cmp  $6, %r14
	jne  .Loik_c10
	mov  %r13, %rdi
	lea  va_revoke(%rip), %rsi
	mov  $6, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
	jmp  .Loik_no
.Loik_c10:
	cmp  $10, %r14
	jne  .Loik_c3
	mov  %r13, %rdi
	lea  va_unregister(%rip), %rsi
	mov  $10, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
	jmp  .Loik_no
.Loik_c3:
	cmp  $3, %r14
	jne  .Loik_no
	mov  %r13, %rdi
	lea  va_put(%rip), %rsi
	mov  $3, %rcx
	call memeq
	test %rax, %rax
	jnz  .Loik_yes
.Loik_no:
	xor  %eax, %eax
	jmp  .Loik_ret
.Loik_yes:
	mov  $1, %eax
.Loik_ret:
	pop  %r14
	pop  %r13
	pop  %rbx
	ret

# =====================================================================
# build_hello_response — construct + send a valid hello EXECUTE_RESPONSE.
# =====================================================================
	.type build_hello_response, @function
build_hello_response:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	# RT-6: (re)start of a connection's handshake — clear any authenticated-latch left over
	# from a prior connection served by this same process (the fork-exhaustion inline-serve
	# fallback in host.s reuses one process across connections; the common fork-per-connection
	# path gets this for free via a fresh, zeroed child .bss).
	movq $0, g_authenticated(%rip)
	# nonce (32 CSPRNG bytes)
	lea  b_nonce(%rip), %rdi
	mov  $32, %rsi
	xor  %edx, %edx
	ksys SYS_getrandom
	# timestamp ms = sec*1000 + nsec/1e6
	xor  %edi, %edi                  # CLOCK_REALTIME
	lea  b_ts(%rip), %rsi
	ksys SYS_clock_gettime
	mov  b_ts(%rip), %rax            # sec
	imul $1000, %rax, %r10
	mov  b_ts+8(%rip), %rax          # nsec
	xor  %edx, %edx
	mov  $1000000, %ecx
	div  %rcx                        # rax = nsec/1e6
	add  %r10, %rax
	mov  %rax, g_ms(%rip)

	# ---- D_hello (a6) into b_dhello ----
	lea  b_dhello(%rip), %r15
	mov  $6, %sil
	call w_map
	lea  k_nonce(%rip), %rdi
	call w_cstr
	lea  b_nonce(%rip), %rsi
	mov  $32, %rdx
	call w_bstr
	lea  k_peerid(%rip), %rdi
	call w_cstr
	lea  g_peerid(%rip), %rsi
	mov  g_peerid_len(%rip), %rdx
	call w_txt
	lea  k_ktypes(%rip), %rdi
	call w_cstr
	mov  $2, %sil
	call w_arr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  v_ed448(%rip), %rdi
	call w_cstr
	lea  k_protos(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  v_ecore(%rip), %rdi
	call w_cstr
	lea  k_ts(%rip), %rdi
	call w_cstr
	mov  g_ms(%rip), %rsi
	call w_uint
	lea  k_hfmts(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  v_ecfv1(%rip), %rdi
	call w_cstr
	# dhello_len = r15 - b_dhello
	lea  b_dhello(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_dhlen(%rip)
	# ch_hello = ec_content_hash("system/protocol/connect/hello"(29), D_hello)
	lea  t_hello(%rip), %rdi
	mov  $29, %rsi
	lea  b_dhello(%rip), %rdx
	mov  g_dhlen(%rip), %rcx
	lea  ch_hello(%rip), %r8
	call ec_content_hash

	# ---- D_resp (a3) into b_dresp ----
	lea  b_dresp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi        # "result" → hello entity
	call w_cstr
	mov  $3, %sil
	call w_map
	lea  k_data(%rip), %rdi
	call w_cstr
	lea  b_dhello(%rip), %rsi        # embed D_hello verbatim
	mov  g_dhlen(%rip), %rdx
	call w_raw
	lea  k_type(%rip), %rdi
	call w_cstr
	lea  t_hello(%rip), %rdi
	call w_cstr
	lea  k_chash(%rip), %rdi
	call w_cstr
	lea  ch_hello(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  k_status(%rip), %rdi        # "status" → 200
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi           # "request_id" → echo
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	# dresp_len
	lea  b_dresp(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_drlen(%rip)
	# ch_resp = ec_content_hash("system/protocol/execute/response"(32), D_resp)
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_dresp(%rip), %rdx
	mov  g_drlen(%rip), %rcx
	lea  ch_resp(%rip), %r8
	call ec_content_hash

	# ---- envelope (a1) into b_env ----
	lea  b_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	mov  $3, %sil
	call w_map
	lea  k_data(%rip), %rdi
	call w_cstr
	lea  b_dresp(%rip), %rsi         # embed D_resp verbatim
	mov  g_drlen(%rip), %rdx
	call w_raw
	lea  k_type(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	call w_cstr
	lea  k_chash(%rip), %rdi
	call w_cstr
	lea  ch_resp(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	# env_len
	lea  b_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # r14 = env len
	# frame header: 4-byte BE len
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# authenticate — verify PoP, mint + sign a capability token, return the grant.
# (Happy path: parse → mint → respond. Nonce/signature REJECTION paths are added
#  next for the handshake enforcement checks.)
# =====================================================================
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
	.lcomm g_authenticated, 8         # RT-6 (§4.6): 0/1, set once authenticate succeeds — a
                                           # second authenticate on this connection must not
                                           # re-verify the (single-use) nonce and re-mint a grant.
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
# w_entity(rdi=type_cstr, rsi=data_ptr, rdx=data_len, rcx=chash_ptr) — emit an
# entity map {data:<raw>, type:<cstr>, content_hash:<33>}. Uses r15 cursor.
	.type w_entity, @function
w_entity:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rdi, %r12                  # type cstr
	mov  %rsi, %r13                  # data ptr
	mov  %rdx, %r14                  # data len
	mov  %rcx, %rbx                  # chash ptr
	mov  $3, %sil
	call w_map
	lea  k_data(%rip), %rdi
	call w_cstr
	mov  %r13, %rsi
	mov  %r14, %rdx
	call w_raw
	lea  k_type(%rip), %rdi
	call w_cstr
	mov  %r12, %rdi
	call w_cstr
	lea  k_chash(%rip), %rdi
	call w_cstr
	mov  %rbx, %rsi
	mov  $33, %rdx
	call w_bstr
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# now_ms() -> rax = wall-clock ms
	.type now_ms, @function
now_ms:
	xor  %edi, %edi
	lea  b_ts(%rip), %rsi
	ksys SYS_clock_gettime
	mov  b_ts(%rip), %rax
	imul $1000, %rax, %r10
	mov  b_ts+8(%rip), %rax
	xor  %edx, %edx
	mov  $1000000, %ecx
	div  %rcx
	add  %r10, %rax
	ret

# emit_grants — emit the grants ARRAY (cursor r15) per g_opengrants.
	.type emit_grants, @function
emit_grants:
	mov  g_opengrants(%rip), %rax
	test %rax, %rax
	jz   .Leg_floor
	mov  $1, %sil
	call w_arr
	jmp  emit_grant_wild
.Leg_floor:
	mov  $2, %sil
	call w_arr
	call emit_grant_floor1
	jmp  emit_grant_floor2

# {peers:[*], handlers:[*], resources:[*,/*/*], operations:[*]}
	.type emit_grant_wild, @function
emit_grant_wild:
	mov  $4, %sil
	call w_map
	lea  ka_peers(%rip), %rdi
	call w_incl1
	lea  ka_handlers(%rip), %rdi
	call w_incl1
	lea  ka_resources(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $2, %sil
	call w_arr
	lea  va_star(%rip), %rdi
	call w_cstr
	lea  va_star2(%rip), %rdi
	call w_cstr
	lea  ka_operations(%rip), %rdi
	call w_incl1
	ret

# w_incl1(rdi=field_cstr) — emit  <field>: {include:["*"]}
	.type w_incl1, @function
w_incl1:
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  va_star(%rip), %rdi
	call w_cstr
	ret

# floor grant 1: {handlers:{include:[system/tree]}, resources:{include:[system/type/*,
#   system/handler/*]}, operations:{include:[get]}}
	.type emit_grant_floor1, @function
emit_grant_floor1:
	mov  $3, %sil
	call w_map
	lea  ka_handlers(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  va_systree(%rip), %rdi
	call w_cstr
	lea  ka_resources(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $2, %sil
	call w_arr
	lea  va_systype_g(%rip), %rdi
	call w_cstr
	lea  va_syshandler_g(%rip), %rdi
	call w_cstr
	lea  ka_operations(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  va_get(%rip), %rdi
	call w_cstr
	ret

# floor grant 2: {handlers:{include:[system/capability]}, resources:{include:[]},
#   operations:{include:[request]}}
	.type emit_grant_floor2, @function
emit_grant_floor2:
	mov  $3, %sil
	call w_map
	lea  ka_handlers(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  va_syscap(%rip), %rdi
	call w_cstr
	lea  ka_resources(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $0, %sil
	call w_arr
	lea  ka_operations(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	lea  ka_include(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_arr
	lea  va_request(%rip), %rdi
	call w_cstr
	ret

# build_authenticate_response(rdi = exec data map ptr)
	.type build_authenticate_response, @function
build_authenticate_response:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # exec data map
	# RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established connection
	# must be rejected outright — the nonce is single-use, so re-verifying it and re-minting
	# a grant would let a captured/replayed authenticate frame mint fresh capabilities.
	cmpq $0, g_authenticated(%rip)
	je   .Lauth_not_replay
	mov  $401, %rdi
	lea  ec_invalid_nonce(%rip), %rsi
	call send_error
	jmp  .Lauth_ret
.Lauth_not_replay:
	# params entity
	mov  %r12, %rdi
	lea  ka_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lauth_ret
	mov  %rax, %r13                  # params entity
	# params data map
	mov  %r13, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	mov  %rax, %r14                  # params data (pdata)
	# §7.1 agility: reject an unsupported key_type at the handshake (400 unsupported_key_type)
	# before the identity checks. key_type must be the text "ed25519" (the core floor); any
	# other value — including the numeric 0xFD experimental code — is unsupported.
	mov  %r14, %rdi
	lea  ka_ktype(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lauth_kt_ok                # absent → lenient (identity checks still run)
	mov  %rax, %rdi
	call read_head                   # rax = text ptr, rcx = major, rdx = len
	cmp  $3, %rcx                    # must be a text string
	jne  .Lauth_bad_kt
	cmp  $7, %rdx
	jne  .Lauth_bad_kt
	mov  %rax, %rdi
	lea  v_ed25519(%rip), %rsi
	mov  $7, %rcx
	call memeq
	test %rax, %rax
	jz   .Lauth_bad_kt
.Lauth_kt_ok:
	# client public_key → g_client_pubkey (32)
	mov  %r14, %rdi
	lea  ka_pubkey(%rip), %rsi
	mov  $10, %rdx
	call map_find
	mov  %rax, %rdi
	call get_text                    # rax=ptr, rdx=len(32)
	lea  g_client_pubkey(%rip), %rdi
	mov  %rax, %rsi
	mov  $32, %rdx
	call mcpy
	# grantee = ec_content_hash("system/peer", client_peer{key_type,public_key})
	lea  b_clientpeer(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  ka_ktype(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_pubkey(%rip), %rdi
	call w_cstr
	lea  g_client_pubkey(%rip), %rsi
	mov  $32, %rdx
	call w_bstr
	lea  b_clientpeer(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx                  # client peer data len
	lea  ta_peer(%rip), %rdi
	mov  $11, %rsi
	lea  b_clientpeer(%rip), %rdx
	lea  g_grantee(%rip), %r8
	call ec_content_hash

	# ================= §5.2 verification (reject → 401) =================
	# 1. nonce echo — params.nonce must equal the nonce we issued (b_nonce)
	mov  %r14, %rdi                  # pdata
	lea  k_nonce(%rip), %rsi
	mov  $5, %rdx
	call map_find
	test %rax, %rax
	jz   .Lauth_bad_nonce
	mov  %rax, %rdi
	call get_text
	cmp  $32, %rdx
	jne  .Lauth_bad_nonce
	mov  %rax, %rdi
	lea  b_nonce(%rip), %rsi
	mov  $32, %rcx
	call memeq
	test %rax, %rax
	jz   .Lauth_bad_nonce
	# 2. peer_id binding — base58(client pubkey) must equal params.peer_id
	mov  $1, %edi
	xor  %esi, %esi
	lea  g_client_pubkey(%rip), %rdx
	mov  $32, %rcx
	lea  b_derived_pid(%rip), %r8
	mov  $128, %r9
	sub  $16, %rsp
	lea  g_derived_pid_len(%rip), %rax
	mov  %rax, (%rsp)
	call ec_peerid_format
	add  $16, %rsp
	mov  %r14, %rdi
	lea  k_peerid(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lauth_bad_pid
	mov  %rax, %rdi
	call get_text                    # rax=ptr, rdx=len
	cmp  g_derived_pid_len(%rip), %rdx
	jne  .Lauth_bad_pid
	mov  %rax, %rdi
	lea  b_derived_pid(%rip), %rsi
	mov  %rdx, %rcx
	call memeq
	test %rax, %rax
	jz   .Lauth_bad_pid
	# 3. PoP signature — verify client sig over the authenticate entity content_hash
	mov  %r14, %rdi
	call skip_value
	sub  %r14, %rax                  # pdata len
	mov  %rax, %rcx
	lea  ta_auth(%rip), %rdi
	mov  $36, %rsi
	mov  %r14, %rdx
	lea  g_auth_hash(%rip), %r8
	call ec_content_hash
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lauth_bad_sig
	mov  %rax, %rdi
	call find_sig_entity
	test %rax, %rax
	jz   .Lauth_bad_sig
	lea  k_data(%rip), %rsi
	mov  %rax, %rdi
	mov  $4, %rdx
	call map_find
	mov  %rax, %r13                  # sig data map
	mov  %r13, %rdi
	lea  ka_sig(%rip), %rsi
	mov  $9, %rdx
	call map_find
	mov  %rax, %rdi
	call get_text                    # rax = sig(64)
	mov  %rax, %rbx
	lea  g_client_pubkey(%rip), %rdi
	lea  g_auth_hash(%rip), %rsi
	mov  $33, %rdx
	mov  %rbx, %rcx
	call ec_ed25519_verify
	test %eax, %eax
	jnz  .Lauth_bad_sig
	# 4. impersonation — signature.signer must equal client identity_hash (grantee)
	mov  %r13, %rdi
	lea  ka_signer(%rip), %rsi
	mov  $6, %rdx
	call map_find
	mov  %rax, %rdi
	call get_text
	mov  %rax, %rdi
	lea  g_grantee(%rip), %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lauth_bad_imp
	# ================= verification passed =================
	movq $1, g_authenticated(%rip)   # RT-6: latch — the next authenticate on this conn is a replay

	call now_ms
	mov  %rax, g_created(%rip)

	# ---- token data ----
	lea  b_tokdata(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_grants(%rip), %rdi
	call w_cstr
	call emit_grants
	lea  ka_grantee(%rip), %rdi
	call w_cstr
	lea  g_grantee(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_granter(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_created(%rip), %rdi
	call w_cstr
	mov  g_created(%rip), %rsi
	call w_uint
	lea  b_tokdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_toklen(%rip)
	# tok_ch = ec_content_hash("system/capability/token", token_data)
	lea  ta_token(%rip), %rdi
	mov  $23, %rsi
	lea  b_tokdata(%rip), %rdx
	mov  g_toklen(%rip), %rcx
	lea  tok_ch(%rip), %r8
	call ec_content_hash
	# tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	lea  g_seed(%rip), %rdi
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	lea  tok_sig(%rip), %rcx
	call ec_ed25519_sign

	# ---- signature entity data {signer,target,algorithm,signature} ----
	lea  b_sigdata(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_signer(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_target(%rip), %rdi
	call w_cstr
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_algo(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_sig(%rip), %rdi
	call w_cstr
	lea  tok_sig(%rip), %rsi
	mov  $64, %rdx
	call w_bstr
	lea  b_sigdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_sigdlen(%rip)
	lea  ta_sig(%rip), %rdi
	mov  $16, %rsi
	lea  b_sigdata(%rip), %rdx
	mov  g_sigdlen(%rip), %rcx
	lea  sig_ch(%rip), %r8
	call ec_content_hash

	# ---- grant result data {token: tok_ch} ----
	lea  b_grantdata(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  ka_token(%rip), %rdi
	call w_cstr
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  b_grantdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_grlen(%rip)
	lea  ta_grant(%rip), %rdi
	mov  $23, %rsi
	lea  b_grantdata(%rip), %rdx
	mov  g_grlen(%rip), %rcx
	lea  grant_ch(%rip), %r8
	call ec_content_hash

	# ---- response data {result, status, request_id} ----
	lea  b_ar_resp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	lea  ta_grant(%rip), %rdi        # result entity = the grant
	lea  b_grantdata(%rip), %rsi
	mov  g_grlen(%rip), %rdx
	lea  grant_ch(%rip), %rcx
	call w_entity
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_ar_resp(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_ardlen(%rip)
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_ar_resp(%rip), %rdx
	mov  g_ardlen(%rip), %rcx
	lea  resp_ch2(%rip), %r8
	call ec_content_hash

	# ---- envelope {root, included} ----
	lea  b_ar_env(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_ar_resp(%rip), %rsi
	mov  g_ardlen(%rip), %rdx
	lea  resp_ch2(%rip), %rcx
	call w_entity
	lea  ka_included(%rip), %rdi
	call w_cstr
	# Populate the included-entry table {key_ptr,type_ptr,data_ptr,data_len,ch_ptr}
	# then emit sorted by 33-byte key — ECF §4.2 canonical map ordering (the three
	# keys are content hashes, so the order is runtime-dependent). 40 bytes/entry.
	lea  b_incl_tab(%rip), %rcx
	# entry 0: token
	lea  tok_ch(%rip), %rax
	mov  %rax, 0(%rcx)
	lea  ta_token(%rip), %rax
	mov  %rax, 8(%rcx)
	lea  b_tokdata(%rip), %rax
	mov  %rax, 16(%rcx)
	mov  g_toklen(%rip), %rax
	mov  %rax, 24(%rcx)
	lea  tok_ch(%rip), %rax
	mov  %rax, 32(%rcx)
	# entry 1: peer (identity)
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 40(%rcx)
	lea  ta_peer(%rip), %rax
	mov  %rax, 48(%rcx)
	lea  b_peerdata(%rip), %rax
	mov  %rax, 56(%rcx)
	mov  g_peerdata_len(%rip), %rax
	mov  %rax, 64(%rcx)
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 72(%rcx)
	# entry 2: signature
	lea  sig_ch(%rip), %rax
	mov  %rax, 80(%rcx)
	lea  ta_sig(%rip), %rax
	mov  %rax, 88(%rcx)
	lea  b_sigdata(%rip), %rax
	mov  %rax, 96(%rcx)
	mov  g_sigdlen(%rip), %rax
	mov  %rax, 104(%rcx)
	lea  sig_ch(%rip), %rax
	mov  %rax, 112(%rcx)
	mov  $3, %edi
	lea  b_incl_tab(%rip), %rsi
	call emit_sorted_included
	# frame + write
	lea  b_ar_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # env len
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_ar_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	jmp  .Lauth_ret
.Lauth_bad_nonce:
	mov  $401, %rdi
	lea  ec_invalid_nonce(%rip), %rsi
	call send_error
	jmp  .Lauth_ret
.Lauth_bad_pid:
	mov  $401, %rdi
	lea  ec_identity_mismatch(%rip), %rsi
	call send_error
	jmp  .Lauth_ret
.Lauth_bad_sig:
	mov  $401, %rdi
	lea  ec_auth_failed(%rip), %rsi
	call send_error
	jmp  .Lauth_ret
.Lauth_bad_imp:
	mov  $401, %rdi
	lea  ec_identity_mismatch(%rip), %rsi
	call send_error
	jmp  .Lauth_ret
.Lauth_bad_kt:
	mov  $400, %rdi
	lea  ec_unsup_kt(%rip), %rsi
	call send_error
.Lauth_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# build_request_response(rdi = exec data map) — the system/capability `request` handler.
# Authorizes the caller with the same §5.2 gate as the get path (401/403 on failure), then
# mints a token whose grants are copied verbatim from params.data.grants (the caller asks for
# the attenuation it wants), grantee = the request author, granter = this peer; signs it and
# returns a 200 system/capability/grant with {token, granter-peer, signature} in included.
	.type build_request_response, @function
build_request_response:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 (odd) → align FFI/send calls
	mov  %rdi, %r12                  # exec
	# authorize: auth-class (401) then capability + grant-scope (403). The handler derived
	# from data.uri is system/capability, op is request — the authenticate-minted floor
	# token grants exactly that, so a legitimately-authenticated caller passes.
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lrq_ret
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lrq_ret
	mov  %r12, %rdi
	call verify_op_scope
	test %rax, %rax
	jnz  .Lrq_ret
	# grantee = request author (33) → g_grantee
	mov  %r12, %rdi
	lea  k_author(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_malformed
	mov  %rax, %rdi
	call get_text
	lea  g_grantee(%rip), %rdi
	mov  %rax, %rsi
	mov  $33, %rdx
	call mcpy
	# requested grants = params.data.grants (raw CBOR array) → g_reqg_ptr/len
	mov  %r12, %rdi
	lea  ka_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_malformed
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_malformed
	mov  %rax, g_params_data(%rip)   # params.data — the §5.6 ttl_ms term lives here
	mov  %rax, %rdi
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_malformed
	mov  %rax, %r13                  # grants value ptr
	mov  %rax, %rdi
	call skip_value                  # rax = end of grants value
	sub  %r13, %rax                  # grants byte length
	mov  %r13, g_reqg_ptr(%rip)
	mov  %rax, g_reqg_len(%rip)
	# attenuation (§6.2): the requested grants MUST NOT widen scope beyond the caller's
	# token. Resolve the caller's token data (data.capability → included) and require every
	# requested grant to be covered by some caller grant, else 403 capability_denied.
	mov  %r12, %rdi
	lea  k_capability(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_denied
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r14                  # caller cap hash
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_denied
	mov  %rax, %rdi
	mov  %r14, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lrq_denied
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_denied
	mov  %rax, %rsi                  # caller token data
	mov  %rax, g_caller_td(%rip)
	mov  %r13, %rdi                  # requested grants array value
	call grants_attenuated
	test %rax, %rax
	jnz  .Lrq_atten_ok
.Lrq_denied:
	mov  $403, %rdi
	lea  ec_cap_denied(%rip), %rsi
	call send_error
	jmp  .Lrq_ret
.Lrq_atten_ok:
	# created_at — sampled ONCE. The duration term below is converted against this same
	# instant; sampling again there emits a token whose stated birth and derived expiry are
	# two different instants.
	call now_ms
	mov  %rax, g_created(%rip)
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
	movq $0, g_exp_have(%rip)
	movq $0, g_expv(%rip)
	mov  g_caller_td(%rip), %rdi
	test %rdi, %rdi
	jz   .Lrq_ttl
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_ttl
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx                  # not a uint64 → unusable, not a term
	jnz  .Lrq_ttl
	mov  %rdx, g_expv(%rip)
	movq $1, g_exp_have(%rip)
.Lrq_ttl:
	mov  g_params_data(%rip), %rdi
	test %rdi, %rdi
	jz   .Lrq_mint
	lea  ka_ttl_ms(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrq_mint
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lrq_mint
	mov  g_created(%rip), %rax
	add  %rdx, %rax
	# §5.6 rule 3: a term that does not fit is DROPPED — never wrapped, never saturated.
	# Saturation would manufacture expires_at == 2^64-1, a finite bound no reader can tell
	# from a deliberate one. ttl_ms == 0 is NOT special-cased (rule 2): it falls out as
	# created_at, which is what keeps "expire immediately" from collapsing into the
	# absent / "no bound" spelling.
	jc   .Lrq_mint
	cmpq $0, g_exp_have(%rip)
	jne  .Lrq_ttl_min
	mov  %rax, g_expv(%rip)
	movq $1, g_exp_have(%rip)
	jmp  .Lrq_mint
.Lrq_ttl_min:
	cmp  g_expv(%rip), %rax
	jae  .Lrq_mint
	mov  %rax, g_expv(%rip)
.Lrq_mint:
	# ---- token data {grants:<raw>, grantee, granter, created_at[, expires_at]} ----
	# Canonical key order is length-then-lex, so expires_at sorts AFTER created_at (same
	# length, c < e) and appends cleanly at the end.
	lea  b_tokdata(%rip), %r15
	mov  $4, %esi
	add  g_exp_have(%rip), %rsi
	call w_map
	lea  ka_grants(%rip), %rdi
	call w_cstr
	mov  g_reqg_ptr(%rip), %rsi
	mov  g_reqg_len(%rip), %rdx
	call w_raw
	lea  ka_grantee(%rip), %rdi
	call w_cstr
	lea  g_grantee(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_granter(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_created(%rip), %rdi
	call w_cstr
	mov  g_created(%rip), %rsi
	call w_uint
	cmpq $0, g_exp_have(%rip)
	je   .Lrq_tokdone
	lea  ka_expires(%rip), %rdi
	call w_cstr
	mov  g_expv(%rip), %rsi
	call w_uint
.Lrq_tokdone:
	lea  b_tokdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_toklen(%rip)
	# shared tail: hash+sign the token, build the grant, emit the 200 response.
	call mint_finish
	jmp  .Lrq_ret
.Lrq_malformed:
	# §4.9(c) deliver-or-signal: a `request` missing author / params / params.data /
	# params.data.grants used to fall off the end of this function and answer NOTHING,
	# leaving the caller to wait out its own timeout — indistinguishable from a dead peer.
	# The branch was unreachable for as long as the capability gate refused every delegated
	# capability two stages earlier; implementing the §5.5 chain walk is what let a request
	# get this far, which is the standing lesson in the other direction — a wrong denial can
	# also hide a missing ANSWER, not just a missing check.
	mov  $400, %rdi
	lea  ec_invalid_params(%rip), %rsi
	call send_error
.Lrq_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# mint_finish — shared token-grant tail (globals-only): given b_tokdata/g_toklen already
# built (and g_grantee consumed into it), compute the token content_hash, Ed25519-sign it as
# this peer, build the system/signature entity + the system/capability/grant result, and emit
# the 200 EXECUTE_RESPONSE with {token, granter-peer, signature} sorted into `included`.
# Used by build_request_response; build_authenticate_response keeps its own inline copy.
	.type mint_finish, @function
mint_finish:
	push %rbx
	push %r14
	push %r15                        # 3 (odd) → align the FFI/write calls
	# tok_ch = ec_content_hash("system/capability/token", token_data)
	lea  ta_token(%rip), %rdi
	mov  $23, %rsi
	lea  b_tokdata(%rip), %rdx
	mov  g_toklen(%rip), %rcx
	lea  tok_ch(%rip), %r8
	call ec_content_hash
	# tok_sig = ec_ed25519_sign(g_seed, tok_ch, 33, out)
	lea  g_seed(%rip), %rdi
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	lea  tok_sig(%rip), %rcx
	call ec_ed25519_sign
	# ---- signature entity data {signer,target,algorithm,signature} ----
	lea  b_sigdata(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_signer(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_target(%rip), %rdi
	call w_cstr
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_algo(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_sig(%rip), %rdi
	call w_cstr
	lea  tok_sig(%rip), %rsi
	mov  $64, %rdx
	call w_bstr
	lea  b_sigdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_sigdlen(%rip)
	lea  ta_sig(%rip), %rdi
	mov  $16, %rsi
	lea  b_sigdata(%rip), %rdx
	mov  g_sigdlen(%rip), %rcx
	lea  sig_ch(%rip), %r8
	call ec_content_hash
	# ---- grant result data {token: tok_ch} ----
	lea  b_grantdata(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  ka_token(%rip), %rdi
	call w_cstr
	lea  tok_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  b_grantdata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_grlen(%rip)
	lea  ta_grant(%rip), %rdi
	mov  $23, %rsi
	lea  b_grantdata(%rip), %rdx
	mov  g_grlen(%rip), %rcx
	lea  grant_ch(%rip), %r8
	call ec_content_hash
	# ---- response data {result, status, request_id} ----
	lea  b_ar_resp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	lea  ta_grant(%rip), %rdi
	lea  b_grantdata(%rip), %rsi
	mov  g_grlen(%rip), %rdx
	lea  grant_ch(%rip), %rcx
	call w_entity
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_ar_resp(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_ardlen(%rip)
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_ar_resp(%rip), %rdx
	mov  g_ardlen(%rip), %rcx
	lea  resp_ch2(%rip), %r8
	call ec_content_hash
	# ---- envelope {root, included} ----
	lea  b_ar_env(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_ar_resp(%rip), %rsi
	mov  g_ardlen(%rip), %rdx
	lea  resp_ch2(%rip), %rcx
	call w_entity
	lea  ka_included(%rip), %rdi
	call w_cstr
	lea  b_incl_tab(%rip), %rcx
	# entry 0: token
	lea  tok_ch(%rip), %rax
	mov  %rax, 0(%rcx)
	lea  ta_token(%rip), %rax
	mov  %rax, 8(%rcx)
	lea  b_tokdata(%rip), %rax
	mov  %rax, 16(%rcx)
	mov  g_toklen(%rip), %rax
	mov  %rax, 24(%rcx)
	lea  tok_ch(%rip), %rax
	mov  %rax, 32(%rcx)
	# entry 1: peer (identity)
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 40(%rcx)
	lea  ta_peer(%rip), %rax
	mov  %rax, 48(%rcx)
	lea  b_peerdata(%rip), %rax
	mov  %rax, 56(%rcx)
	mov  g_peerdata_len(%rip), %rax
	mov  %rax, 64(%rcx)
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 72(%rcx)
	# entry 2: signature
	lea  sig_ch(%rip), %rax
	mov  %rax, 80(%rcx)
	lea  ta_sig(%rip), %rax
	mov  %rax, 88(%rcx)
	lea  b_sigdata(%rip), %rax
	mov  %rax, 96(%rcx)
	mov  g_sigdlen(%rip), %rax
	mov  %rax, 104(%rcx)
	lea  sig_ch(%rip), %rax
	mov  %rax, 112(%rcx)
	mov  $3, %edi
	lea  b_incl_tab(%rip), %rsi
	call emit_sorted_included
	# frame + write
	lea  b_ar_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # env len
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_ar_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	pop  %r15
	pop  %r14
	pop  %rbx
	ret

# send_error(rdi=status, rsi=code_cstr) — emit a status EXECUTE_RESPONSE with a
# system/protocol/error {code} result. No `included`.
	.type send_error, @function
send_error:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # status
	mov  %rsi, %r13                  # code cstr
	lea  b_err(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_code(%rip), %rdi
	call w_cstr
	mov  %r13, %rdi
	call w_cstr
	lea  b_err(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, %r14                  # err data len
	lea  t_error(%rip), %rdi
	mov  $21, %rsi
	lea  b_err(%rip), %rdx
	mov  %r14, %rcx
	lea  err_ch(%rip), %r8
	call ec_content_hash
	lea  b_er_resp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	lea  t_error(%rip), %rdi
	lea  b_err(%rip), %rsi
	mov  %r14, %rdx
	lea  err_ch(%rip), %rcx
	call w_entity
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  %r12, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_er_resp(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, %r14                  # resp data len
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_er_resp(%rip), %rdx
	mov  %r14, %rcx
	lea  er_resp_ch(%rip), %r8
	call ec_content_hash
	lea  b_er_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_er_resp(%rip), %rsi
	mov  %r14, %rdx
	lea  er_resp_ch(%rip), %rcx
	call w_entity
	lea  b_er_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_er_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# serve_tree_get(rdi = exec data map ptr) — resolve resource.targets[0] against the
# embedded read-only type/handler store; 200 with the stored entity, else 404.
# =====================================================================
	.type serve_tree_get, @function
# chain_depth_check(rdi = exec data map) -> rax = 0 ok, 1 rejected (400 chain_depth_exceeded).
# §9.1/§4.10(b) resource floor: follow the presented capability's `parent` chain through
# `included`; a chain deeper than 64 delegations is rejected before the authority walk. A
# cyclic chain terminates the same way (depth passes 64). Server-minted tokens carry no
# parent (depth 0), so the type_system cohort is untouched.
	.type chain_depth_check, @function
chain_depth_check:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5 (odd) → align send_error
	mov  %rdi, %r15                  # exec
	lea  k_capability(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcd_ok                     # no capability → nothing to bound
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r14                  # cur = capability hash ptr (33)
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcd_ok
	mov  %rax, %r13                  # included
	xor  %r12, %r12                 # depth = 0
.Lcd_loop:
	mov  %r13, %rdi
	mov  %r14, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lcd_ok                     # chain ends (unresolvable) → depth within bound
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcd_ok
	mov  %rax, %rdi
	lea  ka_parent(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcd_ok                     # root reached (no parent) → within bound
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r14                  # cur = parent hash
	inc  %r12
	cmp  $64, %r12
	jbe  .Lcd_loop                   # ≤64 delegations → keep walking
	mov  $400, %rdi
	lea  ec_chain_depth(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lcd_ret
.Lcd_ok:
	xor  %eax, %eax
.Lcd_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

	.type serve_tree_get, @function
serve_tree_get:
	push %rbx                         # 3 pushes (odd) → 16B-align the send_*/FFI calls.
	push %r12
	push %r13
	mov  %rdi, %r12                  # exec data map
	# §9.1/§4.10(b) resource floor — reject an over-deep delegation chain (400) up front,
	# before the authority walk, so a maliciously deep chain can't force unbounded work.
	mov  %r12, %rdi
	call chain_depth_check
	test %rax, %rax
	jnz  .Lstg_done                  # 400 chain_depth_exceeded already sent
	# §5.2 auth-class gate — reject unauthenticated/tampered requests (401) before serving.
	mov  %r12, %rdi
	call verify_get_auth             # rdi = exec
	test %rax, %rax
	jnz  .Lstg_done                  # rejected; 401 already sent
	# §5.2 capability-class gate (403) — token present/bound/signed.
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lstg_done                  # rejected; 403 already sent
	# §5.2 grant-scope gate (403 default-deny) — token must permit op×handler×resource.
	mov  %r12, %rdi
	call verify_get_scope
	test %rax, %rax
	jnz  .Lstg_done                  # rejected; 403 already sent
	# resource = map_find(exec, "resource", 8)
	mov  %r12, %rdi
	lea  k_resource(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstg_404
	# targets = map_find(resource, "targets", 7)
	mov  %rax, %rdi
	lea  k_targets(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstg_404
	# rax = targets array value; read head, require ≥1 element
	mov  %rax, %rdi
	call read_head                   # rax=after-head, rcx=major(4), rdx=count
	test %rdx, %rdx
	jz   .Lstg_404
	# first element is a text string → ptr,len
	mov  %rax, %rdi
	call get_text                    # rax=strptr, rdx=strlen
	mov  %rax, %r13                  # raw target ptr
	mov  %rdx, %rbx                  # raw target len
	# §"invalid_path" reject (dot-relative / empty-segment / NUL).
	mov  %r13, %rsi
	mov  %rbx, %rcx
	call path_valid
	test %rax, %rax
	jz   .Lstg_invalid
	# empty target (root) or trailing '/' → listing over the store (§tree get listing).
	test %rbx, %rbx
	jz   .Lstg_listing               # empty = root listing
	cmpb $0x2f, -1(%r13,%rbx)         # last byte == '/'?
	jne  .Lstg_point
.Lstg_listing:
	mov  %r13, %rdi
	mov  %rbx, %rsi
	call serve_tree_listing          # emits its own 200/404
	jmp  .Lstg_done
.Lstg_point:
	# §1.4 canonicalize for the write-store key; the read-only typestore keeps raw keys.
	mov  %r13, %rsi
	mov  %rbx, %rcx
	call canon_path                  # rax=canon ptr, rdx=canon len
	mov  %rax, %rsi
	mov  %rdx, %rcx
	call store_get                   # -> rax=blob|0, rdx=len
	test %rax, %rax
	jnz  .Lstg_send
	mov  %r13, %rsi                  # raw target for the read-only typestore
	mov  %rbx, %rcx
	call typestore_lookup            # -> rax=blobptr|0, rdx=bloblen
	test %rax, %rax
	jz   .Lstg_404
.Lstg_send:
	mov  %rax, %rdi
	mov  %rdx, %rsi
	call send_get_ok
	jmp  .Lstg_done
.Lstg_invalid:
	mov  $400, %rdi
	lea  ec_invalid_path(%rip), %rsi
	call send_error
	jmp  .Lstg_done
.Lstg_404:
	mov  $404, %rdi
	lea  ec_not_found(%rip), %rsi
	call send_error
.Lstg_done:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# typestore_lookup(rsi = target ptr, rcx = target len) -> rax = blob ptr|0, rdx = blob len.
# Linear scan of the generated type_table (the core floor, currently 58 entries;
# the count is read from type_table_count, never assumed); exact string match on the path
# (the listing path "system/type/" carries its trailing slash, so it matches verbatim too).
	.type typestore_lookup, @function
typestore_lookup:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rsi, %r13                  # target ptr
	mov  %rcx, %r14                  # target len
	lea  type_table(%rip), %rbx
	mov  type_table_count(%rip), %r12
.Ltl_loop:
	test %r12, %r12
	jz   .Ltl_none
	mov  8(%rbx), %rax               # entry.path_len
	cmp  %rax, %r14
	jne  .Ltl_next
	mov  0(%rbx), %rdi               # entry.path_ptr
	mov  %r13, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Ltl_found
.Ltl_next:
	add  $32, %rbx
	dec  %r12
	jmp  .Ltl_loop
.Ltl_found:
	mov  16(%rbx), %rax             # entry.blob_ptr
	mov  24(%rbx), %rdx             # entry.blob_len
	jmp  .Ltl_ret
.Ltl_none:
	xor  %eax, %eax
	xor  %edx, %edx
.Ltl_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# send_get_ok(rdi = entity blob ptr, rsi = entity blob len) — emit a 200 EXECUTE_RESPONSE
# whose `result` is the pre-serialized stored entity, copied verbatim (w_raw). Mirrors
# send_error's envelope construction.
	.type send_get_ok, @function
send_get_ok:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # blob ptr
	mov  %rsi, %r13                  # blob len
	# ---- data map {result:<blob>, status:200, request_id:<rid>} ----
	lea  b_get_data(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	mov  %r12, %rsi
	mov  %r13, %rdx
	call w_raw
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_get_data(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # r14 = data len
	# content_hash of the response entity
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_get_data(%rip), %rdx
	mov  %r14, %rcx
	lea  get_data_ch(%rip), %r8
	call ec_content_hash
	# ---- envelope {root: <resp entity>} ----
	lea  b_get_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_get_data(%rip), %rsi
	mov  %r14, %rdx
	lea  get_data_ch(%rip), %rcx
	call w_entity
	# ---- frame (4-byte BE len) + send ----
	lea  b_get_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_get_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# A-ASM-011 — per-fork write store (path→entity). store_idx is an array of 32-byte entries
# [0]=path_ptr [8]=path_len [16]=blob_ptr [24]=blob_len, pointing into store_arena where the
# bytes are copied out of the per-frame-reused b_req so they persist across the connection.
# =====================================================================

# store_get(rsi = path ptr, rcx = path len) -> rax = blob ptr|0, rdx = blob len.
# Preserves rsi/rcx so the caller can fall through to the read-only typestore_lookup.
	.type store_get, @function
store_get:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5 (odd) → align
	mov  %rsi, %r13                  # path ptr
	mov  %rcx, %r14                  # path len
	lea  store_idx(%rip), %rbx
	mov  store_count(%rip), %r12
.Lsg_loop:
	test %r12, %r12
	jz   .Lsg_none
	mov  8(%rbx), %rax               # entry.path_len
	cmp  %rax, %r14
	jne  .Lsg_next
	mov  0(%rbx), %rdi               # entry.path_ptr
	mov  %r13, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lsg_found
.Lsg_next:
	add  $32, %rbx
	dec  %r12
	jmp  .Lsg_loop
.Lsg_found:
	mov  16(%rbx), %rax             # blob ptr
	mov  24(%rbx), %rdx             # blob len
	jmp  .Lsg_ret
.Lsg_none:
	xor  %eax, %eax
	xor  %edx, %edx
.Lsg_ret:
	mov  %r13, %rsi                 # restore path ptr/len for the caller's fallback
	mov  %r14, %rcx
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# store_put(rdi = path ptr, rsi = path len, rdx = blob ptr, rcx = blob len).
# Overwrites an existing binding in place (new blob appended to the arena), else appends a
# new entry. r10 holds the scan counter across memeq (memeq never touches r10).
	.type store_put, @function
store_put:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5 (odd)
	mov  %rdi, %r12                  # path ptr
	mov  %rsi, %r13                  # path len
	mov  %rdx, %r14                  # blob ptr
	mov  %rcx, %r15                  # blob len
	# arena capacity guard — never write past store_arena (would corrupt neighbouring .bss).
	mov  store_used(%rip), %rax
	add  %r13, %rax
	add  %r15, %rax
	cmp  $STORE_ARENA_CAP, %rax
	ja   .Lsp_ret
	lea  store_idx(%rip), %rbx
	mov  store_count(%rip), %r10
.Lsp_scan:
	test %r10, %r10
	jz   .Lsp_new
	mov  8(%rbx), %rax               # entry.path_len
	cmp  %rax, %r13
	jne  .Lsp_scan_next
	mov  0(%rbx), %rdi
	mov  %r12, %rsi
	mov  %r13, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lsp_overwrite
.Lsp_scan_next:
	add  $32, %rbx
	dec  %r10
	jmp  .Lsp_scan
.Lsp_overwrite:
	# rbx = matching entry — append new blob to the arena, repoint the entry.
	lea  store_arena(%rip), %rdi
	add  store_used(%rip), %rdi
	mov  %rdi, 16(%rbx)             # entry.blob_ptr = dst
	mov  %r15, 24(%rbx)             # entry.blob_len
	mov  %r14, %rsi
	mov  %r15, %rdx
	call mcpy
	mov  store_used(%rip), %rax
	add  %r15, %rax
	mov  %rax, store_used(%rip)
	jmp  .Lsp_ret
.Lsp_new:
	mov  store_count(%rip), %rax
	cmp  $STORE_MAX, %rax            # index-full guard — drop rather than overrun store_idx
	jae  .Lsp_ret
	shl  $5, %rax                    # *32
	lea  store_idx(%rip), %rbx
	add  %rax, %rbx                  # rbx = new entry slot
	lea  store_arena(%rip), %rdi
	add  store_used(%rip), %rdi      # dst = arena + used
	mov  %rdi, 0(%rbx)              # entry.path_ptr
	mov  %r13, 8(%rbx)              # entry.path_len
	mov  %r12, %rsi                 # path src
	mov  %r13, %rdx
	call mcpy                        # rax = dst + path_len = blob dst
	mov  %rax, 16(%rbx)            # entry.blob_ptr
	mov  %r15, 24(%rbx)            # entry.blob_len
	mov  %rax, %rdi
	mov  %r14, %rsi                 # blob src
	mov  %r15, %rdx
	call mcpy
	mov  store_used(%rip), %rax
	add  %r13, %rax
	add  %r15, %rax
	mov  %rax, store_used(%rip)
	incq store_count(%rip)
.Lsp_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# canon_path(rsi = path ptr, rcx = path len) -> rax = canon ptr, rdx = canon len.
# §1.4 universal address space: a peer-relative path `foo` canonicalizes to the absolute
# `/{localPeerID}/foo`; an already-absolute `/…` path (incl. foreign namespaces) is verbatim.
# Relative results are built into b_canon; absolute results alias the input.
	.type canon_path, @function
canon_path:
	test %rcx, %rcx
	jz   .Lcp_asis
	cmpb $0x2f, (%rsi)               # leading '/' → already absolute
	je   .Lcp_asis
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 (odd)
	mov  %rsi, %r13                  # path ptr
	mov  %rcx, %r14                  # path len
	lea  b_canon(%rip), %r12
	movb $0x2f, (%r12)               # '/'
	inc  %r12
	mov  %r12, %rdi
	lea  g_peerid(%rip), %rsi
	mov  g_peerid_len(%rip), %rdx
	call mcpy                        # rax = dst end
	mov  %rax, %r12
	movb $0x2f, (%r12)               # '/'
	inc  %r12
	mov  %r12, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	call mcpy                        # rax = end of canon
	lea  b_canon(%rip), %rdx
	sub  %rdx, %rax                  # rax = canon len
	mov  %rax, %rdx                  # rdx = canon len
	lea  b_canon(%rip), %rax         # rax = canon ptr
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret
.Lcp_asis:
	mov  %rsi, %rax
	mov  %rcx, %rdx
	ret

# path_valid(rsi = path ptr, rcx = path len) -> rax = 1 valid / 0 invalid.
# §"invalid_path": rejects a NUL byte, an empty non-leading segment ("//"), and any "."/".."
# segment (dot-relative). A single trailing '/' (listing) and a single leading '/' (absolute)
# are allowed; Unicode segments are accepted (only the byte rules above apply).
	.type path_valid, @function
path_valid:
	push %rbx
	# §1.4: caller-supplied paths are peer-relative; a leading '/' means an absolute
	# /{peerID}/… address, so the first segment must be peer-id-length. A short leading
	# segment ("/system/…") is a mis-scoped caller path → invalid_path.
	test %rcx, %rcx
	jz   .Lpv_body
	cmpb $0x2f, (%rsi)
	jne  .Lpv_body
	mov  $1, %r8
.Lpv_fs:
	cmp  %rcx, %r8
	jae  .Lpv_fsdone
	cmpb $0x2f, (%rsi,%r8)
	je   .Lpv_fsdone
	inc  %r8
	jmp  .Lpv_fs
.Lpv_fsdone:
	dec  %r8                         # first-segment length
	cmp  $32, %r8
	jb   .Lpv_bad
.Lpv_body:
	xor  %r8, %r8                    # i
	xor  %r9, %r9                    # seg_start
.Lpv_loop:
	cmp  %rcx, %r8
	jae  .Lpv_final
	movzbl (%rsi,%r8), %eax
	test %al, %al
	jz   .Lpv_bad                    # NUL
	cmp  $0x2f, %al                  # '/'
	jne  .Lpv_next
	mov  %r8, %rbx
	sub  %r9, %rbx                   # seg_len
	test %rbx, %rbx
	jnz  .Lpv_checkdot
	test %r9, %r9                    # empty segment: OK only when leading (seg_start==0)
	jnz  .Lpv_bad
	jmp  .Lpv_advance
.Lpv_checkdot:
	cmp  $1, %rbx
	jne  .Lpv_checkdd
	cmpb $0x2e, (%rsi,%r9)           # "."
	je   .Lpv_bad
	jmp  .Lpv_advance
.Lpv_checkdd:
	cmp  $2, %rbx
	jne  .Lpv_advance
	cmpb $0x2e, (%rsi,%r9)
	jne  .Lpv_advance
	lea  1(%r9), %rax
	cmpb $0x2e, (%rsi,%rax)          # ".."
	je   .Lpv_bad
.Lpv_advance:
	lea  1(%r8), %r9
.Lpv_next:
	inc  %r8
	jmp  .Lpv_loop
.Lpv_final:
	mov  %rcx, %rbx
	sub  %r9, %rbx                   # final seg len
	test %rbx, %rbx
	jz   .Lpv_ok                     # trailing '/' or empty → allow
	cmp  $1, %rbx
	jne  .Lpv_fdd
	cmpb $0x2e, (%rsi,%r9)
	je   .Lpv_bad
	jmp  .Lpv_ok
.Lpv_fdd:
	cmp  $2, %rbx
	jne  .Lpv_ok
	cmpb $0x2e, (%rsi,%r9)
	jne  .Lpv_ok
	lea  1(%r9), %rax
	cmpb $0x2e, (%rsi,%rax)
	je   .Lpv_bad
.Lpv_ok:
	mov  $1, %eax
	pop  %rbx
	ret
.Lpv_bad:
	xor  %eax, %eax
	pop  %rbx
	ret

# cas_check(rdi = params.data map, rsi = path ptr, rdx = path len) -> rax = 0 ok / 1 conflict.
# §"tree put" CAS: expected_hash absent → unconditional. all-zero(33B) → path must be ABSENT
# (create). nonzero → path must exist and its entity's content_hash must equal expected_hash.
	.type cas_check, @function
cas_check:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5
	mov  %rsi, %r13                  # path ptr
	mov  %rdx, %r14                  # path len
	mov  %rdi, %r12                  # params.data
	mov  %r12, %rdi
	lea  k_expected(%rip), %rsi
	mov  $13, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcas_ok                    # absent → unconditional put
	mov  %rax, %rdi
	call get_text                    # rax=exp ptr, rdx=exp len
	mov  %rax, %r15                  # expected hash ptr
	mov  %rdx, %rcx                  # exp len
	xor  %r8, %r8                     # OR-accumulator (0 ⇒ all-zero)
	xor  %r9, %r9
.Lcas_zscan:
	cmp  %rcx, %r9
	jae  .Lcas_zdone
	movzbl (%r15,%r9), %eax
	or   %eax, %r8d
	inc  %r9
	jmp  .Lcas_zscan
.Lcas_zdone:
	mov  %r13, %rsi
	mov  %r14, %rcx
	call store_get                   # rax=cur blob|0, rdx=len
	test %r8, %r8
	jnz  .Lcas_nonzero
	# expected all-zero → require ABSENT
	test %rax, %rax
	jnz  .Lcas_conflict
	jmp  .Lcas_ok
.Lcas_nonzero:
	# require PRESENT with matching content_hash
	test %rax, %rax
	jz   .Lcas_conflict
	mov  %rax, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lcas_conflict
	mov  %rax, %rdi
	call get_text                    # rax=cur chash ptr
	mov  %rax, %rdi
	mov  %r15, %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lcas_conflict
	jmp  .Lcas_ok
.Lcas_conflict:
	mov  $1, %eax
	jmp  .Lcas_ret
.Lcas_ok:
	xor  %eax, %eax
.Lcas_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# serve_tree_put(rdi = exec data map) — §5.2-gated write of params.data.entity at
# resource.targets[0] into the per-fork store; 200 system/tree/put-result{content_hash}.
# =====================================================================
	.type serve_tree_put, @function
serve_tree_put:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5 (odd) → align
	mov  %rdi, %r12                  # exec
	mov  %r12, %rdi
	call chain_depth_check
	test %rax, %rax
	jnz  .Lstp_done
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lstp_done
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lstp_done
	mov  %r12, %rdi
	call verify_get_scope
	test %rax, %rax
	jnz  .Lstp_done
	# path = resource.targets[0]
	mov  %r12, %rdi
	lea  k_resource(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %rdi
	lea  k_targets(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %rdi
	call read_head                   # rdx = count
	test %rdx, %rdx
	jz   .Lstp_400
	mov  %rax, %rdi
	call get_text                    # rax=path ptr, rdx=path len
	mov  %rax, %r13
	mov  %rdx, %r14
	# §"invalid_path" reject (dot-relative / empty-segment / NUL) before any write.
	mov  %r13, %rsi
	mov  %r14, %rcx
	call path_valid
	test %rax, %rax
	jz   .Lstp_invalid
	# §1.4 canonicalize the store key (peer-relative → /{localPeerID}/…).
	mov  %r13, %rsi
	mov  %r14, %rcx
	call canon_path                  # rax=canon ptr, rdx=canon len
	mov  %rax, %r13
	mov  %rdx, %r14
	# entity = params.data.entity
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %r15                  # params.data map
	mov  %rax, %rdi
	lea  k_entity(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %rbx                  # entity blob start (into b_req)
	# CAS pre-check
	mov  %r15, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	call cas_check
	test %rax, %rax
	jnz  .Lstp_409
	# blob len = skip_value(entity) - entity
	mov  %rbx, %rdi
	call skip_value                  # rax = entity end
	sub  %rbx, %rax                  # rax = blob len
	mov  %r13, %rdi
	mov  %r14, %rsi
	mov  %rbx, %rdx
	mov  %rax, %rcx
	call store_put
	# put-result content_hash = the stored entity's own content_hash field (§1.8 recompute-equal)
	mov  %rbx, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lstp_400
	mov  %rax, %rdi
	call get_text                    # rax = chash ptr (33B)
	mov  %rax, %rdi
	call send_put_ok
	jmp  .Lstp_done
.Lstp_409:
	mov  $409, %rdi
	lea  ec_hash_mismatch(%rip), %rsi
	call send_error
	jmp  .Lstp_done
.Lstp_invalid:
	mov  $400, %rdi
	lea  ec_invalid_path(%rip), %rsi
	call send_error
	jmp  .Lstp_done
.Lstp_400:
	mov  $400, %rdi
	lea  ec_unexpected_params(%rip), %rsi
	call send_error
.Lstp_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# send_put_ok(rdi = 33-byte content_hash ptr) — 200 EXECUTE_RESPONSE whose result is a
# freshly-built system/tree/put-result{content_hash} entity. Mirrors send_error's envelope.
	.type send_put_ok, @function
send_put_ok:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                         # 5
	mov  %rdi, %r12                  # chash ptr (33B)
	# ---- put-result inner data {content_hash:<33B>} ----
	lea  b_prd_data(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_chash(%rip), %rdi
	call w_cstr
	mov  %r12, %rsi
	mov  $33, %rdx
	call w_bstr
	lea  b_prd_data(%rip), %rax
	mov  %r15, %r13
	sub  %rax, %r13                  # r13 = prd data len
	lea  t_put_result(%rip), %rdi
	mov  $22, %rsi
	lea  b_prd_data(%rip), %rdx
	mov  %r13, %rcx
	lea  prd_ch(%rip), %r8
	call ec_content_hash
	# ---- response data {result:<put-result entity>, status:200, request_id} ----
	lea  b_put_resp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	lea  t_put_result(%rip), %rdi
	lea  b_prd_data(%rip), %rsi
	mov  %r13, %rdx
	lea  prd_ch(%rip), %rcx
	call w_entity
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_put_resp(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # r14 = resp data len
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_put_resp(%rip), %rdx
	mov  %r14, %rcx
	lea  put_resp_ch(%rip), %r8
	call ec_content_hash
	# ---- envelope {root:<resp entity>} ----
	lea  b_put_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_put_resp(%rip), %rsi
	mov  %r14, %rdx
	lea  put_resp_ch(%rip), %rcx
	call w_entity
	# ---- frame + send ----
	lea  b_put_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_put_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# system/handler register / unregister (writes handler entities to the per-fork store).
# =====================================================================

# find_raw(rdi=map, rsi=key cstr, rdx=key len) -> rax = value ptr|0, rdx = value byte-length.
# Returns the verbatim CBOR span of a map value (head + body), for embedding via w_raw.
	.type find_raw, @function
find_raw:
	push %r12
	call map_find
	test %rax, %rax
	jz   .Lfr_none
	mov  %rax, %r12
	mov  %rax, %rdi
	call skip_value                  # rax = end
	sub  %r12, %rax
	mov  %rax, %rdx
	mov  %r12, %rax
	pop  %r12
	ret
.Lfr_none:
	xor  %eax, %eax
	xor  %edx, %edx
	pop  %r12
	ret

# mk_entity(rdi=type cstr, rsi=type len, rdx=data ptr, rcx=data len, r8=chash out buf) ->
# rax = entity byte-length. Hashes the data, writes the {data,type,content_hash} entity into
# the shared b_ent_scratch (reg_store copies it out immediately after).
	.type mk_entity, @function
mk_entity:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # type cstr
	mov  %rsi, %r13                  # type len
	mov  %rdx, %rbx                  # data ptr
	mov  %rcx, %r14                  # data len
	mov  %r8, g_chbuf(%rip)
	mov  %r12, %rdi
	mov  %r13, %rsi
	mov  %rbx, %rdx
	mov  %r14, %rcx
	mov  g_chbuf(%rip), %r8
	call ec_content_hash
	lea  b_ent_scratch(%rip), %r15
	mov  %r12, %rdi
	mov  %rbx, %rsi
	mov  %r14, %rdx
	mov  g_chbuf(%rip), %rcx
	call w_entity
	lea  b_ent_scratch(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx                  # entlen
	mov  %rdx, %rax
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# reg_store(rdi=path ptr, rsi=path len, rdx=blob ptr, rcx=blob len) — canonicalize the path
# (§1.4) and store the entity blob under it.
	.type reg_store, @function
reg_store:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdx, %r14                  # blob ptr
	mov  %rcx, %r15                  # blob len
	mov  %rsi, %rcx
	mov  %rdi, %rsi
	call canon_path                  # rax=canon ptr, rdx=canon len
	mov  %rax, %rdi
	mov  %rdx, %rsi
	mov  %r14, %rdx
	mov  %r15, %rcx
	call store_put
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# pcat(rdi=prefix ptr, rsi=prefix len, rdx=seg ptr, rcx=seg len) -> rax=b_hpath ptr, rdx=len.
	.type pcat, @function
pcat:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %rbx                  # prefix ptr
	mov  %rsi, %r12                  # prefix len
	mov  %rdx, %r13                  # seg ptr
	mov  %rcx, %r14                  # seg len
	lea  b_hpath(%rip), %rdi
	mov  %rbx, %rsi
	mov  %r12, %rdx
	call mcpy                        # rax = dst + preflen
	mov  %rax, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	call mcpy
	lea  b_hpath(%rip), %rax
	mov  %r12, %rdx
	add  %r14, %rdx
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# hexenc(rdi=src 33-byte ptr, rsi=dst ptr) — write 66 lowercase hex chars.
	.type hexenc, @function
hexenc:
	push %rbx
	xor  %rcx, %rcx
.Lhx:
	cmp  $33, %rcx
	jae  .Lhx_done
	movzbl (%rdi,%rcx), %eax
	mov  %eax, %ebx
	shr  $4, %ebx
	lea  hexchars(%rip), %rdx
	movzbl (%rdx,%rbx), %ebx
	mov  %bl, (%rsi)
	inc  %rsi
	movzbl (%rdi,%rcx), %eax
	and  $0xf, %eax
	lea  hexchars(%rip), %rdx
	movzbl (%rdx,%rax), %eax
	mov  %al, (%rsi)
	inc  %rsi
	inc  %rcx
	jmp  .Lhx
.Lhx_done:
	pop  %rbx
	ret

# serve_register(rdi = exec data map) — §5.2-gated system/handler register. Writes 4 entities
# to the store (interface, handler, capability token, signature) and returns 200
# system/handler/register-result {grant, pattern}.
	.type serve_register, @function
serve_register:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # exec
	mov  %r12, %rdi
	call chain_depth_check
	test %rax, %rax
	jnz  .Lsr_done
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lsr_done
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lsr_done
	mov  %r12, %rdi
	call verify_get_scope
	test %rax, %rax
	jnz  .Lsr_done
	# params.data → r13
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsr_400
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsr_400
	mov  %rax, %r13                  # params.data
	# manifest → r14
	mov  %r13, %rdi
	lea  k_manifest(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsr_400
	mov  %rax, %r14                  # manifest map
	# pattern content → g_hpat
	mov  %r14, %rdi
	lea  k_pattern(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsr_400
	mov  %rax, %rdi
	call get_text
	mov  %rax, g_hpat_ptr(%rip)
	mov  %rdx, g_hpat_len(%rip)
	# ── §6.2 reserved-pattern guard ─────────────────────────────────────
	# user-installed handlers MUST NOT register at system/* paths. Runs
	# right after the pattern is extracted but BEFORE any of the five
	# normative writes below (interface/handler/token/signature/response).
	# Reserved iff pattern == "system" (len 6, exact) or pattern starts
	# with "system/" (len >= 7, prefix).
	mov  g_hpat_len(%rip), %rax
	cmp  $7, %rax
	jl   .Lsr_pat_chk6
	mov  g_hpat_ptr(%rip), %rdi
	lea  p_sys_slash(%rip), %rsi
	mov  $7, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lsr_reserved
	jmp  .Lsr_pat_ok
.Lsr_pat_chk6:
	cmp  $6, %rax
	jne  .Lsr_pat_ok
	mov  g_hpat_ptr(%rip), %rdi
	lea  p_sys_bare(%rip), %rsi
	mov  $6, %rcx
	call memeq
	test %rax, %rax
	jz   .Lsr_pat_ok
.Lsr_reserved:
	mov  $403, %rdi
	lea  ec_forbidden_pattern(%rip), %rsi
	call send_error
	jmp  .Lsr_done
.Lsr_pat_ok:
	# interface store path = "system/handler/" + pattern → save into b_ipath
	lea  p_hnd_slash(%rip), %rdi
	mov  $15, %rsi
	mov  g_hpat_ptr(%rip), %rdx
	mov  g_hpat_len(%rip), %rcx
	call pcat                        # rax=b_hpath, rdx=len
	mov  %rdx, g_ipath_len(%rip)
	lea  b_ipath(%rip), %rdi
	mov  %rax, %rsi
	mov  %rdx, %rdx
	call mcpy

	# ===== 1. interface entity {name, pattern, operations} =====
	lea  b_iface_data(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_name(%rip), %rdi
	call w_cstr
	mov  %r14, %rdi
	lea  k_name(%rip), %rsi
	mov  $4, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  k_pattern(%rip), %rdi
	call w_cstr
	mov  %r14, %rdi
	lea  k_pattern(%rip), %rsi
	mov  $7, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  ka_operations(%rip), %rdi
	call w_cstr
	mov  %r14, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  b_iface_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_iface(%rip), %rdi
	mov  $24, %rsi
	lea  b_iface_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  iface_ch(%rip), %r8
	call mk_entity                   # rax = entlen; blob in b_ent_scratch
	# store at b_ipath
	mov  %rax, %rcx                  # blob len
	lea  b_ipath(%rip), %rdi
	mov  g_ipath_len(%rip), %rsi
	lea  b_ent_scratch(%rip), %rdx
	call reg_store

	# ===== 2. handler entity {interface, internal_scope, expression_path} =====
	lea  b_hdlr_data(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_interface(%rip), %rdi
	call w_cstr
	lea  b_ipath(%rip), %rsi
	mov  g_ipath_len(%rip), %rdx
	call w_txt
	lea  k_internal_scope(%rip), %rdi
	call w_cstr
	mov  %r14, %rdi
	lea  k_internal_scope(%rip), %rsi
	mov  $14, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  k_expr_path(%rip), %rdi
	call w_cstr
	mov  %r14, %rdi
	lea  k_expr_path(%rip), %rsi
	mov  $15, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  b_hdlr_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_handler(%rip), %rdi
	mov  $14, %rsi
	lea  b_hdlr_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  hdlr_ch(%rip), %r8
	call mk_entity
	mov  %rax, %rcx
	mov  g_hpat_ptr(%rip), %rdi
	mov  g_hpat_len(%rip), %rsi
	lea  b_ent_scratch(%rip), %rdx
	call reg_store

	# ===== 3. capability token {grants, grantee, granter, created_at} =====
	call now_ms
	mov  %rax, g_created(%rip)
	lea  b_htok_data(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_grants(%rip), %rdi
	call w_cstr
	mov  %r13, %rdi
	lea  k_req_scope(%rip), %rsi
	mov  $15, %rdx
	call find_raw
	mov  %rax, %rsi
	call w_raw
	lea  ka_grantee(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_granter(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_created(%rip), %rdi
	call w_cstr
	mov  g_created(%rip), %rsi
	call w_uint
	lea  b_htok_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_htoklen(%rip)
	lea  ta_token(%rip), %rdi
	mov  $23, %rsi
	lea  b_htok_data(%rip), %rdx
	mov  g_htoklen(%rip), %rcx
	lea  htok_ch(%rip), %r8
	call mk_entity
	# token store path = "system/capability/grants/" + pattern
	mov  %rax, %r15                  # entlen
	lea  p_cap_grants(%rip), %rdi
	mov  $25, %rsi
	mov  g_hpat_ptr(%rip), %rdx
	mov  g_hpat_len(%rip), %rcx
	call pcat                        # rax=b_hpath, rdx=len
	mov  %rax, %rdi
	mov  %rdx, %rsi
	lea  b_ent_scratch(%rip), %rdx
	mov  %r15, %rcx
	call reg_store

	# ===== 4. signature {signer, target, algorithm, signature} over the token hash =====
	lea  g_seed(%rip), %rdi
	lea  htok_ch(%rip), %rsi
	mov  $33, %rdx
	lea  htok_sig(%rip), %rcx
	call ec_ed25519_sign
	lea  b_hsig_data(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_signer(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_target(%rip), %rdi
	call w_cstr
	lea  htok_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_algo(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_sig(%rip), %rdi
	call w_cstr
	lea  htok_sig(%rip), %rsi
	mov  $64, %rdx
	call w_bstr
	lea  b_hsig_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  ta_sig(%rip), %rdi
	mov  $16, %rsi
	lea  b_hsig_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  hsig_ch(%rip), %r8
	call mk_entity
	# sig store path = "system/signature/" + hex(htok_ch)
	mov  %rax, %r15                  # entlen
	lea  htok_ch(%rip), %rdi
	lea  b_hex(%rip), %rsi
	call hexenc
	lea  p_sig_slash(%rip), %rdi
	mov  $17, %rsi
	lea  b_hex(%rip), %rdx
	mov  $66, %rcx
	call pcat
	mov  %rax, %rdi
	mov  %rdx, %rsi
	lea  b_ent_scratch(%rip), %rdx
	mov  %r15, %rcx
	call reg_store

	# ===== register-result {grant:<token data>, pattern} =====
	lea  b_regres_data(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  k_grant(%rip), %rdi
	call w_cstr
	lea  b_htok_data(%rip), %rsi
	mov  g_htoklen(%rip), %rdx
	call w_raw
	lea  k_pattern(%rip), %rdi
	call w_cstr
	mov  g_hpat_ptr(%rip), %rsi
	mov  g_hpat_len(%rip), %rdx
	call w_txt
	lea  b_regres_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_reg_result(%rip), %rdi
	mov  $30, %rsi
	lea  b_regres_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  regres_ch(%rip), %r8
	call mk_entity                   # entity → b_ent_scratch
	# wrap as the response result via send_get_ok
	mov  %rax, %rsi                  # entlen
	lea  b_ent_scratch(%rip), %rdi
	call send_get_ok
	jmp  .Lsr_done
.Lsr_400:
	mov  $400, %rdi
	lea  ec_unexpected_params(%rip), %rsi
	call send_error
.Lsr_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# serve_unregister(rdi = exec data map) — remove the handler entities for the pattern named by
# resource.targets[0] (= system/handler/<pattern>). Deletes interface, handler, token and the
# invariant-path signature, then returns 200 with a null result entity.
	.type serve_unregister, @function
serve_unregister:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # exec
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lsu_done
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lsu_done
	mov  %r12, %rdi
	call verify_get_scope
	test %rax, %rax
	jnz  .Lsu_done
	# target = resource.targets[0]  (= system/handler/<pattern>)
	mov  %r12, %rdi
	lea  k_resource(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsu_ok
	mov  %rax, %rdi
	lea  k_targets(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsu_ok
	mov  %rax, %rdi
	call read_head
	test %rdx, %rdx
	jz   .Lsu_ok
	mov  %rax, %rdi
	call get_text                    # rax=target ptr, rdx=target len (= interface path)
	mov  %rax, %r13                  # target ptr
	mov  %rdx, %r14                  # target len
	# pattern = target after the "system/handler/" (15-byte) prefix
	lea  15(%r13), %r15              # pattern ptr
	mov  %r14, %rbx
	sub  $15, %rbx                   # pattern len
	# token path = "system/capability/grants/" + pattern → look it up for its content_hash
	lea  p_cap_grants(%rip), %rdi
	mov  $25, %rsi
	mov  %r15, %rdx
	mov  %rbx, %rcx
	call pcat                        # rax=b_hpath, rdx=len
	mov  %rax, %rsi
	mov  %rdx, %rcx
	call canon_path                  # rax=canon, rdx=len
	mov  %rax, %rsi
	mov  %rdx, %rcx
	call store_get                   # rax=token blob|0
	test %rax, %rax
	jz   .Lsu_delrest
	# recompute sig path from the token's content_hash field → delete it
	mov  %rax, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsu_delrest
	mov  %rax, %rdi
	call get_text                    # rax = 33-byte token hash ptr
	mov  %rax, %rdi
	lea  b_hex(%rip), %rsi
	call hexenc
	lea  p_sig_slash(%rip), %rdi
	mov  $17, %rsi
	lea  b_hex(%rip), %rdx
	mov  $66, %rcx
	call pcat
	mov  %rax, %rdi
	mov  %rdx, %rsi
	call store_delete
.Lsu_delrest:
	# delete interface (= target), handler (= pattern), token (= grants path)
	mov  %r13, %rdi
	mov  %r14, %rsi
	call store_delete
	mov  %r15, %rdi
	mov  %rbx, %rsi
	call store_delete
	lea  p_cap_grants(%rip), %rdi
	mov  $25, %rsi
	mov  %r15, %rdx
	mov  %rbx, %rcx
	call pcat
	mov  %rax, %rdi
	mov  %rdx, %rsi
	call store_delete
.Lsu_ok:
	# 200 with a null result entity {data:null, type:"", content_hash:<33 zero>}
	lea  b_regres_env(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_data(%rip), %rdi
	call w_cstr
	movb $0xf6, (%r15)               # null
	inc  %r15
	lea  k_type(%rip), %rdi
	call w_cstr
	movb $0x60, (%r15)               # empty text ""
	inc  %r15
	lea  k_chash(%rip), %rdi
	call w_cstr
	lea  b_zero33(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  b_regres_env(%rip), %rax
	mov  %r15, %rsi
	sub  %rax, %rsi
	lea  b_regres_env(%rip), %rdi
	call send_get_ok
.Lsu_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# serve_configure(rdi = exec data map) — §system/capability configure. Writes a peer
# policy-entry; accepts both canonical-hex and Base58 peer_pattern forms (§3.6). The 200
# result echoes the params policy-entry entity verbatim.
	.type serve_configure, @function
serve_configure:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # exec
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lsc_done
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lsc_done
	# NB: no verify_get_scope — a configure request carries no resource.targets (the peer
	# policy names its scope via params.data.grants), so the target-based scope gate does not
	# apply; auth + capability presence is the gate.
	# params entity (raw span) → r13 ptr, r14 len (echoed + stored).
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsc_400
	mov  %rax, %r13                  # params entity start
	mov  %rax, %rdi
	call skip_value
	sub  %r13, %rax
	mov  %rax, %r14                  # params entity len
	# peer_pattern = params.data.peer_pattern
	mov  %r13, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsc_400
	mov  %rax, %rdi
	lea  k_peer_pattern(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsc_store                  # no peer_pattern → nothing to validate/index
	mov  %rax, %rdi
	call get_text                    # rax=pat ptr, rdx=pat len
	mov  %rax, %r15                  # pattern ptr
	mov  %rdx, %rbx                  # pattern len
	# §V7 §4 reject a partial-prefix wildcard peer_pattern (any '*') → 400 invalid_params.
	xor  %rcx, %rcx
.Lsc_wc:
	cmp  %rbx, %rcx
	jae  .Lsc_wc_ok
	cmpb $0x2a, (%r15,%rcx)          # '*'
	je   .Lsc_invalid
	inc  %rcx
	jmp  .Lsc_wc
.Lsc_wc_ok:
	# store the policy-entry at system/capability/policy/<peer_pattern>
	lea  p_cap_policy(%rip), %rdi
	mov  $25, %rsi
	mov  %r15, %rdx
	mov  %rbx, %rcx
	call pcat                        # rax=b_hpath, rdx=len
	mov  %rax, %rdi
	mov  %rdx, %rsi
	mov  %r13, %rdx
	mov  %r14, %rcx
	call reg_store
.Lsc_store:
	# echo the params policy-entry entity verbatim as the 200 result
	mov  %r13, %rdi
	mov  %r14, %rsi
	call send_get_ok
	jmp  .Lsc_done
.Lsc_invalid:
	mov  $400, %rdi
	lea  ec_invalid_params(%rip), %rsi
	call send_error
	jmp  .Lsc_done
.Lsc_400:
	mov  $400, %rdi
	lea  ec_unexpected_params(%rip), %rsi
	call send_error
.Lsc_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# serve_delegate(rdi = exec) — §6.9a delegate. v1 is same-peer-only; a request with a parent
# field is unsupported (501, construct the attenuated child client-side); one lacking the
# required parent field is malformed (400 invalid_params).
	.type serve_delegate, @function
serve_delegate:
	push %rbx
	push %r12
	push %r13                        # 3
	mov  %rdi, %r12
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdl2_501
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdl2_501
	mov  %rax, %rdi
	lea  ka_parent(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdl2_noparent
.Lsdl2_501:
	mov  $501, %rdi
	lea  ec_unsupported_op(%rip), %rsi
	call send_error
	jmp  .Lsdl2_done
.Lsdl2_noparent:
	mov  $400, %rdi
	lea  ec_invalid_params(%rip), %rsi
	call send_error
.Lsdl2_done:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# serve_revoke(rdi = exec) — §6.9a revoke. Writes a system/capability/revocation marker at
# system/capability/revocations/<hex(token)> and returns 200 with the revocation entity. A
# zero token is rejected (400 invalid_params).
	.type serve_revoke, @function
serve_revoke:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # exec
	mov  %r12, %rdi
	call verify_get_auth
	test %rax, %rax
	jnz  .Lrv_done
	mov  %r12, %rdi
	call verify_get_cap
	test %rax, %rax
	jnz  .Lrv_done
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrv_400
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrv_400
	mov  %rax, %r13                  # params.data
	# token (33B) → r14
	mov  %r13, %rdi
	lea  ka_token(%rip), %rsi
	mov  $5, %rdx
	call map_find
	test %rax, %rax
	jz   .Lrv_400
	mov  %rax, %rdi
	call get_text                    # rax=token ptr, rdx=len
	cmp  $33, %rdx
	jne  .Lrv_400
	mov  %rax, %r14                  # token ptr
	# reject an all-zero token
	xor  %rcx, %rcx
	xor  %r8, %r8
.Lrv_zscan:
	cmp  $33, %rcx
	jae  .Lrv_zdone
	movzbl (%r14,%rcx), %eax
	or   %eax, %r8d
	inc  %rcx
	jmp  .Lrv_zscan
.Lrv_zdone:
	test %r8, %r8
	jz   .Lrv_invalid                # all-zero token
	call now_ms
	mov  %rax, g_created(%rip)
	# reason (verbatim) if present
	mov  %r13, %rdi
	lea  k_reason(%rip), %rsi
	mov  $6, %rdx
	call find_raw
	mov  %rax, %rbx                  # reason value ptr (0 if absent)
	mov  %rdx, g_tmplen(%rip)        # reason len
	# ---- revocation data ----
	lea  b_revoke_data(%rip), %r15
	test %rbx, %rbx
	jz   .Lrv_map2
	mov  $3, %sil
	call w_map
	jmp  .Lrv_tok
.Lrv_map2:
	mov  $2, %sil
	call w_map
.Lrv_tok:
	lea  ka_token(%rip), %rdi
	call w_cstr
	mov  %r14, %rsi
	mov  $33, %rdx
	call w_bstr
	test %rbx, %rbx
	jz   .Lrv_revat
	lea  k_reason(%rip), %rdi
	call w_cstr
	mov  %rbx, %rsi
	mov  g_tmplen(%rip), %rdx
	call w_raw
.Lrv_revat:
	lea  k_revoked_at(%rip), %rdi
	call w_cstr
	mov  g_created(%rip), %rsi
	call w_uint
	lea  b_revoke_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_revocation(%rip), %rdi
	mov  $28, %rsi
	lea  b_revoke_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  revoke_ch(%rip), %r8
	call mk_entity                   # rax=entlen; entity in b_ent_scratch
	mov  %rax, %r15                  # entlen
	# store at system/capability/revocations/<hex(token)>
	mov  %r14, %rdi
	lea  b_hex(%rip), %rsi
	call hexenc
	lea  p_cap_revoke(%rip), %rdi
	mov  $30, %rsi
	lea  b_hex(%rip), %rdx
	mov  $66, %rcx
	call pcat
	mov  %rax, %rdi
	mov  %rdx, %rsi
	lea  b_ent_scratch(%rip), %rdx
	mov  %r15, %rcx
	call reg_store
	# 200 result = the revocation entity
	lea  b_ent_scratch(%rip), %rdi
	mov  %r15, %rsi
	call send_get_ok
	jmp  .Lrv_done
.Lrv_invalid:
	mov  $400, %rdi
	lea  ec_invalid_params(%rip), %rsi
	call send_error
	jmp  .Lrv_done
.Lrv_400:
	mov  $400, %rdi
	lea  ec_unexpected_params(%rip), %rsi
	call send_error
.Lrv_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# is_revoked(rdi = 33-byte token hash) -> rax = 1 if a revocation marker exists in the store.
	.type is_revoked, @function
is_revoked:
	push %rbx
	push %r12
	push %r13                        # 3
	mov  %rdi, %r13
	lea  b_hex(%rip), %rsi
	call hexenc
	lea  p_cap_revoke(%rip), %rdi
	mov  $30, %rsi
	lea  b_hex(%rip), %rdx
	mov  $66, %rcx
	call pcat                        # rax=b_hpath, rdx=len
	mov  %rax, %rsi
	mov  %rdx, %rcx
	call canon_path                  # rax=canon, rdx=len
	mov  %rax, %rsi
	mov  %rdx, %rcx
	call store_get                   # rax=blob|0
	test %rax, %rax
	setnz %al
	movzbl %al, %eax
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# seed_one(rdi=pattern ptr, rsi=pattern len, rdx=interface ptr, rcx=interface len) — publish a
# §6.2 native dispatch entity  {interface:<interface>}  (type system/handler, no expression_path
# ⇒ dispatch_type native) at the bare pattern path.
	.type seed_one, @function
seed_one:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # pattern ptr
	mov  %rsi, %r13                  # pattern len
	mov  %rdx, %rbx                  # interface ptr
	mov  %rcx, %r14                  # interface len
	lea  b_hdlr_data(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_interface(%rip), %rdi
	call w_cstr
	mov  %rbx, %rsi
	mov  %r14, %rdx
	call w_txt
	lea  b_hdlr_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_handler(%rip), %rdi
	mov  $14, %rsi
	lea  b_hdlr_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  hdlr_ch(%rip), %r8
	call mk_entity                   # rax = entlen
	mov  %rax, %rcx
	mov  %r12, %rdi
	mov  %r13, %rsi
	lea  b_ent_scratch(%rip), %rdx
	call reg_store
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# seed_dispatch_entities — publish the built-in native dispatch entities (§6.2 N2/N5) into the
# per-fork store so a get at system/{tree,protocol/connect,capability} resolves a system/handler
# entity with an `interface` ref. Called once per connection (per fork).
	.type seed_dispatch_entities, @function
seed_dispatch_entities:
	push %r12                        # 1 (odd) → align
	lea  va_systree(%rip), %rdi
	mov  $11, %rsi
	lea  s_iface_tree(%rip), %rdx
	mov  $26, %rcx
	call seed_one
	lea  s_pat_connect(%rip), %rdi
	mov  $23, %rsi
	lea  s_iface_connect(%rip), %rdx
	mov  $38, %rcx
	call seed_one
	lea  va_syscap(%rip), %rdi
	mov  $17, %rsi
	lea  s_iface_cap(%rip), %rdx
	mov  $32, %rcx
	call seed_one
	# §7a validate scaffold — publishing system/handler/system/validate/dispatch-outbound is
	# the oracle's --validate gate for BOTH validate_echo_dispatch and t1_2_concurrent_reentry.
	lea  s_name_echo(%rip), %rdi
	lea  s_pat_echo(%rip), %rsi
	lea  va_echo(%rip), %rdx
	lea  s_iface_echo(%rip), %rcx
	call seed_vh
	lea  s_name_dout(%rip), %rdi
	lea  s_pat_dout(%rip), %rsi
	lea  va_dispatch(%rip), %rdx
	lea  s_iface_dout(%rip), %rcx
	call seed_vh
	pop  %r12
	ret

# seed_vh(rdi=name cstr, rsi=pattern cstr, rdx=op cstr, rcx=interface cstr) — publish a
# validate handler: interface {name,pattern,operations:{op:{input_type,output_type}}} at the
# interface path + a native dispatch entity at the pattern path. Lengths via strlen.
	.type seed_vh, @function
seed_vh:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # name
	mov  %rsi, %r13                  # pattern
	mov  %rdx, %rbx                  # op
	mov  %rcx, %r14                  # interface
	lea  b_iface_data(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_name(%rip), %rdi
	call w_cstr
	mov  %r12, %rdi
	call w_cstr
	lea  k_pattern(%rip), %rdi
	call w_cstr
	mov  %r13, %rdi
	call w_cstr
	lea  ka_operations(%rip), %rdi
	call w_cstr
	mov  $1, %sil
	call w_map
	mov  %rbx, %rdi                  # op key
	call w_cstr
	mov  $2, %sil
	call w_map
	lea  k_input_type(%rip), %rdi
	call w_cstr
	lea  v_prim_any(%rip), %rdi
	call w_cstr
	lea  k_output_type(%rip), %rdi
	call w_cstr
	lea  v_prim_any(%rip), %rdi
	call w_cstr
	lea  b_iface_data(%rip), %rax
	mov  %r15, %rcx
	sub  %rax, %rcx
	mov  %rcx, g_tmplen(%rip)
	lea  t_iface(%rip), %rdi
	mov  $24, %rsi
	lea  b_iface_data(%rip), %rdx
	mov  g_tmplen(%rip), %rcx
	lea  iface_ch(%rip), %r8
	call mk_entity
	mov  %rax, %r15                  # entlen
	mov  %r14, %rdi
	call strlen                      # rax = interface len
	mov  %rax, %rsi
	mov  %r14, %rdi
	lea  b_ent_scratch(%rip), %rdx
	mov  %r15, %rcx
	call reg_store
	# native dispatch entity at the pattern path
	mov  %r13, %rdi
	call strlen                      # rax = pattern len
	mov  %rax, %r12                  # pattern len
	mov  %r14, %rdi
	call strlen                      # rax = interface len
	mov  %rax, %rcx                  # ifacelen (seed_one arg 4)
	mov  %r13, %rdi
	mov  %r12, %rsi
	mov  %r14, %rdx
	call seed_one
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# gen_erid — build a unique outbound-echo request_id "e<hex>" into b_erid (len → g_erid_len).
	.type gen_erid, @function
gen_erid:
	mov  echo_ctr(%rip), %rax
	lea  b_erid(%rip), %rdi
	movb $0x65, (%rdi)               # 'e'
	mov  %rax, %rcx
	shr  $4, %rcx
	and  $0xf, %rcx
	lea  hexchars(%rip), %rdx
	movzbl (%rdx,%rcx), %ecx
	mov  %cl, 1(%rdi)
	mov  %rax, %rcx
	and  $0xf, %rcx
	lea  hexchars(%rip), %rdx
	movzbl (%rdx,%rcx), %ecx
	mov  %cl, 2(%rdi)
	movq $3, g_erid_len(%rip)
	incq echo_ctr(%rip)
	ret

# fill_incl(rdi=incl entry ptr, rsi=parent map, rdx=key cstr, rcx=key len, r8=type cstr) —
# populate a 40-byte emit_sorted_included entry from a parent[key] sub-entity:
# [0]=chash(key) [8]=type [16]=data ptr [24]=data len [32]=chash.
	.type fill_incl, @function
fill_incl:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # entry
	mov  %r8, %r14                   # type cstr
	mov  %rsi, %rdi                  # parent
	mov  %rdx, %rsi                  # key
	mov  %rcx, %rdx                  # keylen
	call map_find                    # rax = entity map
	test %rax, %rax
	jz   .Lfi_ret
	mov  %rax, %r13                  # entity
	# content_hash
	mov  %r13, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfi_ret
	mov  %rax, %rdi
	call get_text                    # rax = chash ptr
	mov  %rax, 0(%r12)
	mov  %rax, 32(%r12)
	mov  %r14, 8(%r12)
	# data span
	mov  %r13, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfi_ret
	mov  %rax, 16(%r12)
	mov  %rax, %rdi
	call skip_value
	mov  16(%r12), %rcx
	sub  %rcx, %rax                  # data len
	mov  %rax, 24(%r12)
.Lfi_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# serve_dispatch_outbound(rdi = exec) — §7a.2a: originate a reentry echo EXECUTE to the target
# peer (the validator, same socket) using the handed-in reentry_capability, and record the
# pending dispatch so its response is emitted when the echo reply arrives (handle_dispatch_response).
	.type serve_dispatch_outbound, @function
serve_dispatch_outbound:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # exec
	# pd = exec.params.data → r13
	mov  %r12, %rdi
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdo_ret
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdo_ret
	mov  %rax, %r13                  # pd
	# target text
	mov  %r13, %rdi
	lea  k_target(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdo_ret
	mov  %rax, %rdi
	call get_text
	mov  %rax, g_dtarget_ptr(%rip)
	mov  %rdx, g_dtarget_len(%rip)
	# rcap_hash = reentry_capability.content_hash
	mov  %r13, %rdi
	lea  k_reentry_capability(%rip), %rsi
	mov  $18, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdo_ret
	mov  %rax, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lsdo_ret
	mov  %rax, %rdi
	call get_text
	mov  %rax, g_rcap_hash(%rip)
	# ---- echo params entity {data:<value map>, type:primitive/any, content_hash} ----
	mov  %r13, %rdi
	lea  k_value(%rip), %rsi
	mov  $5, %rdx
	call find_raw                    # rax=value map ptr, rdx=len
	mov  %rax, g_dvalue_ptr(%rip)
	mov  %rdx, g_dvalue_len(%rip)
	lea  t_prim_any(%rip), %rdi
	mov  $13, %rsi
	mov  g_dvalue_ptr(%rip), %rdx
	mov  g_dvalue_len(%rip), %rcx
	lea  eparams_ch(%rip), %r8
	call ec_content_hash
	lea  b_eparams(%rip), %r15
	lea  t_prim_any(%rip), %rdi
	mov  g_dvalue_ptr(%rip), %rsi
	mov  g_dvalue_len(%rip), %rdx
	lea  eparams_ch(%rip), %rcx
	call w_entity                    # echo params entity → b_eparams
	lea  b_eparams(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_eplen(%rip)         # echo params entity len
	# ---- EXECUTE data {uri, author, params, operation, capability, request_id} ----
	call gen_erid
	lea  b_edata(%rip), %r15
	mov  $6, %sil
	call w_map
	lea  k_uri(%rip), %rdi
	call w_cstr
	mov  g_dtarget_ptr(%rip), %rsi
	mov  g_dtarget_len(%rip), %rdx
	call w_txt
	lea  k_author(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_params(%rip), %rdi
	call w_cstr
	lea  b_eparams(%rip), %rsi
	mov  g_eplen(%rip), %rdx
	call w_raw
	lea  k_op(%rip), %rdi
	call w_cstr
	lea  va_echo(%rip), %rdi
	call w_cstr
	lea  k_capability(%rip), %rdi
	call w_cstr
	mov  g_rcap_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  k_rid(%rip), %rdi
	call w_cstr
	lea  b_erid(%rip), %rsi
	mov  g_erid_len(%rip), %rdx
	call w_txt
	lea  b_edata(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_edlen(%rip)
	# ch(execute data)
	lea  t_execute(%rip), %rdi
	mov  $23, %rsi
	lea  b_edata(%rip), %rdx
	mov  g_edlen(%rip), %rcx
	lea  edata_ch(%rip), %r8
	call ec_content_hash
	# ---- our PoP signature over the EXECUTE hash ----
	lea  g_seed(%rip), %rdi
	lea  edata_ch(%rip), %rsi
	mov  $33, %rdx
	lea  esig_bytes(%rip), %rcx
	call ec_ed25519_sign
	lea  b_esig(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  ka_signer(%rip), %rdi
	call w_cstr
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_target(%rip), %rdi
	call w_cstr
	lea  edata_ch(%rip), %rsi
	mov  $33, %rdx
	call w_bstr
	lea  ka_algo(%rip), %rdi
	call w_cstr
	lea  v_ed25519(%rip), %rdi
	call w_cstr
	lea  ka_sig(%rip), %rdi
	call w_cstr
	lea  esig_bytes(%rip), %rsi
	mov  $64, %rdx
	call w_bstr
	lea  b_esig(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, %r14                  # esig data len
	lea  ta_sig(%rip), %rdi
	mov  $16, %rsi
	lea  b_esig(%rip), %rdx
	mov  %r14, %rcx
	lea  esig_ch(%rip), %r8
	call ec_content_hash
	# ---- included table: 5 entries ----
	lea  do_incl_tab(%rip), %rbx
	# entry 0: our peer
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 0(%rbx)
	lea  ta_peer(%rip), %rax
	mov  %rax, 8(%rbx)
	lea  b_peerdata(%rip), %rax
	mov  %rax, 16(%rbx)
	mov  g_peerdata_len(%rip), %rax
	mov  %rax, 24(%rbx)
	lea  g_identity_hash(%rip), %rax
	mov  %rax, 32(%rbx)
	# entry 1: our PoP signature
	lea  esig_ch(%rip), %rax
	mov  %rax, 40(%rbx)
	lea  ta_sig(%rip), %rax
	mov  %rax, 48(%rbx)
	lea  b_esig(%rip), %rax
	mov  %rax, 56(%rbx)
	mov  %r14, 64(%rbx)
	lea  esig_ch(%rip), %rax
	mov  %rax, 72(%rbx)
	# entry 2: reentry_capability
	lea  80(%rbx), %rdi
	mov  %r13, %rsi
	lea  k_reentry_capability(%rip), %rdx
	mov  $18, %rcx
	lea  ta_token(%rip), %r8
	call fill_incl
	# entry 3: reentry_granter (granter peer)
	lea  120(%rbx), %rdi
	mov  %r13, %rsi
	lea  k_reentry_granter(%rip), %rdx
	mov  $15, %rcx
	lea  ta_peer(%rip), %r8
	call fill_incl
	# entry 4: reentry_cap_signature
	lea  160(%rbx), %rdi
	mov  %r13, %rsi
	lea  k_reentry_cap_signature(%rip), %rdx
	mov  $21, %rcx
	lea  ta_sig(%rip), %r8
	call fill_incl
	# ---- envelope {root:<EXECUTE entity>, included} ----
	lea  b_do_env(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_execute(%rip), %rdi
	lea  b_edata(%rip), %rsi
	mov  g_edlen(%rip), %rdx
	lea  edata_ch(%rip), %rcx
	call w_entity
	lea  ka_included(%rip), %rdi
	call w_cstr
	mov  $5, %edi
	lea  do_incl_tab(%rip), %rsi
	call emit_sorted_included
	# ---- frame + send to the validator (as B) on this connection ----
	lea  b_do_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_do_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
	# ---- record pending {echo_rid → dispatch request_id} ----
	mov  pending_n(%rip), %rax
	cmp  $16, %rax
	jae  .Lsdo_ret                   # table full — drop
	imul $80, %rax, %rcx
	lea  pending_tab(%rip), %rbx
	add  %rcx, %rbx                  # entry
	# copy echo_rid
	lea  b_erid(%rip), %rsi
	mov  %rbx, %rdi
	mov  g_erid_len(%rip), %rdx
	call mcpy
	mov  g_erid_len(%rip), %rax
	mov  %rax, 32(%rbx)
	# copy dispatch request_id (g_rid)
	lea  40(%rbx), %rdi
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call mcpy
	mov  g_rid_len(%rip), %rax
	mov  %rax, 72(%rbx)
	incq pending_n(%rip)
.Lsdo_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# handle_dispatch_response(rdi = response root.data map = {result, status, request_id}) —
# match the echo reply's request_id to a pending dispatch-outbound and emit its 200 response
# {result:{type:primitive/any, data:{result:<echo result>, status:<echo status>}}, status:200}.
	.type handle_dispatch_response, @function
handle_dispatch_response:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r12                  # response data
	# request_id → find pending entry
	mov  %r12, %rdi
	lea  k_rid(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhdr_ret
	mov  %rax, %rdi
	call get_text                    # rax=erid ptr, rdx=erid len
	mov  %rax, %r13                  # erid ptr
	mov  %rdx, %r14                  # erid len
	lea  pending_tab(%rip), %rbx
	mov  pending_n(%rip), %r15
	xor  %r10, %r10
.Lhdr_scan:
	cmp  %r15, %r10
	jae  .Lhdr_ret                   # no match (unknown response)
	mov  %r10, %rax
	imul $80, %rax, %rax
	lea  pending_tab(%rip), %rbx
	add  %rax, %rbx
	mov  32(%rbx), %rax              # entry.erid_len
	cmp  %rax, %r14
	jne  .Lhdr_next
	mov  %rbx, %rdi
	mov  %r13, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lhdr_found
.Lhdr_next:
	inc  %r10
	jmp  .Lhdr_scan
.Lhdr_found:
	# save the dispatch request_id (rbx+40, len rbx+72) into g_rid so send helpers echo it
	lea  40(%rbx), %rax
	mov  %rax, g_rid_ptr(%rip)
	mov  72(%rbx), %rax
	mov  %rax, g_rid_len(%rip)
	# echo result entity (raw span) = response.result
	mov  %r12, %rdi
	lea  k_result(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhdr_ret
	mov  %rax, %r13                  # echo result entity ptr
	mov  %rax, %rdi
	call skip_value
	sub  %r13, %rax
	mov  %rax, %r14                  # echo result len
	# ---- inner {result:<echo result>, status:200} ----
	lea  b_do_inner(%rip), %r15
	mov  $2, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	mov  %r13, %rsi
	mov  %r14, %rdx
	call w_raw
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  b_do_inner(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, %r14                  # inner len
	lea  t_prim_any(%rip), %rdi
	mov  $13, %rsi
	lea  b_do_inner(%rip), %rdx
	mov  %r14, %rcx
	lea  do_inner_ch(%rip), %r8
	call ec_content_hash
	# ---- response data {result:<outer result entity>, status:200, request_id} ----
	lea  b_do_data(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	lea  t_prim_any(%rip), %rdi
	lea  b_do_inner(%rip), %rsi
	mov  %r14, %rdx
	lea  do_inner_ch(%rip), %rcx
	call w_entity
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_do_data(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # response data len
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_do_data(%rip), %rdx
	mov  %r14, %rcx
	lea  do_data_ch(%rip), %r8
	call ec_content_hash
	# ---- envelope {root:<response entity>} ----
	lea  b_do_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_do_data(%rip), %rsi
	mov  %r14, %rdx
	lea  do_data_ch(%rip), %rcx
	call w_entity
	lea  b_do_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_do_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
.Lhdr_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# store_delete(rdi = path ptr, rsi = path len) — canonicalize, remove the matching store entry
# (swap-with-last, decrement count). No-op if absent.
	.type store_delete, @function
store_delete:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rsi, %rcx
	mov  %rdi, %rsi
	call canon_path                  # rax=canon, rdx=len
	mov  %rax, %r13
	mov  %rdx, %r14
	lea  store_idx(%rip), %rbx
	mov  store_count(%rip), %r12
.Lsdl_scan:
	test %r12, %r12
	jz   .Lsdl_ret
	mov  8(%rbx), %rax
	cmp  %rax, %r14
	jne  .Lsdl_next
	mov  0(%rbx), %rdi
	mov  %r13, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lsdl_found
.Lsdl_next:
	add  $32, %rbx
	dec  %r12
	jmp  .Lsdl_scan
.Lsdl_found:
	mov  store_count(%rip), %rax
	dec  %rax
	shl  $5, %rax
	lea  store_idx(%rip), %rcx
	add  %rax, %rcx                  # rcx = last entry
	mov  0(%rcx), %rax
	mov  %rax, 0(%rbx)
	mov  8(%rcx), %rax
	mov  %rax, 8(%rbx)
	mov  16(%rcx), %rax
	mov  %rax, 16(%rbx)
	mov  24(%rcx), %rax
	mov  %rax, 24(%rbx)
	decq store_count(%rip)
.Lsdl_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# serve_tree_listing(rdi = raw prefix ptr, rsi = raw prefix len) — a trailing-slash tree get.
# Scans the per-fork store for canonical keys under /{localPeerID}/{prefix} (or under an
# absolute prefix verbatim), groups by immediate child segment, and emits a 200
# system/tree/listing {path, count, offset, entries:{seg→{hash, has_children}}}. Empty →
# falls back to the read-only typestore listing (system/type/) else a 200 empty listing.
	.type serve_tree_listing, @function
serve_tree_listing:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, g_lprefix_ptr(%rip)
	mov  %rsi, g_lprefix_len(%rip)
	mov  %rsi, %rcx
	mov  %rdi, %rsi
	call canon_path                  # rax=cprefix ptr, rdx=cprefix len
	mov  %rax, g_cpref_ptr(%rip)
	mov  %rdx, g_cpref_len(%rip)
	movq $0, listing_n(%rip)
	lea  store_idx(%rip), %rbx
	mov  store_count(%rip), %r12
.Lstl_scan:
	test %r12, %r12
	jz   .Lstl_emit
	mov  8(%rbx), %r13               # Klen
	mov  g_cpref_len(%rip), %rax
	cmp  %rax, %r13
	jb   .Lstl_next                  # key shorter than prefix
	mov  0(%rbx), %rdi
	mov  g_cpref_ptr(%rip), %rsi
	mov  g_cpref_len(%rip), %rcx
	call memeq
	test %rax, %rax
	jz   .Lstl_next
	mov  0(%rbx), %r14
	add  g_cpref_len(%rip), %r14      # rest ptr
	mov  %r13, %r15
	sub  g_cpref_len(%rip), %r15      # restlen
	test %r15, %r15
	jz   .Lstl_next                  # exact prefix (the node itself)
	xor  %rcx, %rcx                  # j = index of first '/'
.Lstl_slash:
	cmp  %r15, %rcx
	jae  .Lstl_slashdone
	cmpb $0x2f, (%r14,%rcx)
	je   .Lstl_slashdone
	inc  %rcx
	jmp  .Lstl_slash
.Lstl_slashdone:
	mov  %r14, %rdi                  # seg ptr
	mov  %rcx, %rsi                  # seg len (= j)
	xor  %r8, %r8
	cmp  %r15, %rsi                  # j < restlen → has deeper segment
	jae  .Lstl_add
	mov  $1, %r8
.Lstl_add:
	mov  16(%rbx), %rdx              # blob ptr (leaf hash source)
	call add_listing_entry
.Lstl_next:
	add  $32, %rbx
	dec  %r12
	jmp  .Lstl_scan
.Lstl_emit:
	mov  listing_n(%rip), %rax
	test %rax, %rax
	jnz  .Lstl_build
	# no store children — fall back to the read-only typestore listing key, else 200 empty.
	mov  g_lprefix_ptr(%rip), %rsi
	mov  g_lprefix_len(%rip), %rcx
	call typestore_lookup
	test %rax, %rax
	jz   .Lstl_build                 # nothing → emit an empty listing
	mov  %rax, %rdi
	mov  %rdx, %rsi
	call send_get_ok
	jmp  .Lstl_done
.Lstl_build:
	call emit_listing
.Lstl_done:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# add_listing_entry(rdi=seg ptr, rsi=seg len, rdx=blob ptr, r8=has_child) — insert-or-merge a
# child segment into listing_ents. A segment seen as both leaf and parent becomes has_children
# with a null hash (matching the reference: intermediate nodes carry hash:null).
	.type add_listing_entry, @function
add_listing_entry:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rdi, %r13                  # seg ptr
	mov  %rsi, %r14                  # seg len
	mov  %rdx, %r15                  # blob ptr
	mov  %r8, %r12                   # has_child
	# §6.3 — a leaf bound to a system/deletion-marker is omitted from listings.
	test %r12, %r12
	jnz  .Lale_notmarker
	mov  %r15, %rdi
	lea  k_type(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lale_notmarker
	mov  %rax, %rdi
	call get_text                    # rax=type ptr, rdx=len
	cmp  $22, %rdx
	jne  .Lale_notmarker
	mov  %rax, %rdi
	lea  t_deletion_marker(%rip), %rsi
	mov  $22, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lale_ret                   # deletion-marker leaf → skip
.Lale_notmarker:
	lea  listing_ents(%rip), %rbx
	mov  listing_n(%rip), %r10
.Lale_scan:
	test %r10, %r10
	jz   .Lale_new
	mov  8(%rbx), %rax
	cmp  %rax, %r14
	jne  .Lale_scannext
	mov  0(%rbx), %rdi
	mov  %r13, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lale_found
.Lale_scannext:
	add  $32, %rbx
	dec  %r10
	jmp  .Lale_scan
.Lale_found:
	test %r12, %r12
	jz   .Lale_ret                   # existing entry already covers this segment
	movq $1, 24(%rbx)                # promote to parent
	movq $0, 16(%rbx)                # parent hash is null
	jmp  .Lale_ret
.Lale_new:
	mov  listing_n(%rip), %rax
	cmp  $384, %rax
	jae  .Lale_ret                   # cap guard
	shl  $5, %rax
	lea  listing_ents(%rip), %rbx
	add  %rax, %rbx
	mov  %r13, 0(%rbx)
	mov  %r14, 8(%rbx)
	test %r12, %r12
	jnz  .Lale_parent
	# leaf: hash = blob's content_hash field
	mov  %r15, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lale_hashnull
	mov  %rax, %rdi
	call get_text                    # rax = chash ptr
	mov  %rax, 16(%rbx)
	jmp  .Lale_setchild
.Lale_hashnull:
	movq $0, 16(%rbx)
	jmp  .Lale_setchild
.Lale_parent:
	movq $0, 16(%rbx)
.Lale_setchild:
	mov  %r12, 24(%rbx)
	incq listing_n(%rip)
.Lale_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# sort_listing — bubble-sort listing_ents by (seg_len, then bytewise) for canonical map order.
	.type sort_listing, @function
sort_listing:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  listing_n(%rip), %r12
	cmp  $2, %r12
	jb   .Lsl_ret
.Lsl_outer:
	xor  %r13, %r13                  # i
	xor  %r14, %r14                  # swapped flag
	lea  listing_ents(%rip), %rbx
.Lsl_inner:
	mov  %r12, %rax
	dec  %rax
	cmp  %rax, %r13
	jae  .Lsl_outer_end
	# compare entry[i] (rbx) vs entry[i+1] (rbx+32)
	mov  8(%rbx), %rdi               # a.len
	mov  40(%rbx), %rsi              # b.len
	cmp  %rsi, %rdi
	ja   .Lsl_swap                   # a longer → a after b
	jb   .Lsl_noswap
	# equal length → bytewise compare a vs b
	mov  0(%rbx), %rdi
	mov  32(%rbx), %rsi
	mov  8(%rbx), %rcx
	call mcmp_lex                    # rax = -1/0/1
	cmp  $0, %eax
	jg   .Lsl_swap
	jmp  .Lsl_noswap
.Lsl_swap:
	# swap the two 32-byte entries via a stack scratch
	mov  0(%rbx),  %rax ; mov 32(%rbx), %rcx ; mov %rcx, 0(%rbx)  ; mov %rax, 32(%rbx)
	mov  8(%rbx),  %rax ; mov 40(%rbx), %rcx ; mov %rcx, 8(%rbx)  ; mov %rax, 40(%rbx)
	mov  16(%rbx), %rax ; mov 48(%rbx), %rcx ; mov %rcx, 16(%rbx) ; mov %rax, 48(%rbx)
	mov  24(%rbx), %rax ; mov 56(%rbx), %rcx ; mov %rcx, 24(%rbx) ; mov %rax, 56(%rbx)
	mov  $1, %r14
.Lsl_noswap:
	add  $32, %rbx
	inc  %r13
	jmp  .Lsl_inner
.Lsl_outer_end:
	test %r14, %r14
	jnz  .Lsl_outer
.Lsl_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# mcmp_lex(rdi=a, rsi=b, rcx=len) -> eax = -1 if a<b, 0 if equal, 1 if a>b (bytewise).
	.type mcmp_lex, @function
mcmp_lex:
.Lmcl:	test %rcx, %rcx
	jz   .Lmcl_eq
	movzbl (%rdi), %eax
	movzbl (%rsi), %edx
	cmp  %edx, %eax
	jb   .Lmcl_lt
	ja   .Lmcl_gt
	inc  %rdi
	inc  %rsi
	dec  %rcx
	jmp  .Lmcl
.Lmcl_eq:
	xor  %eax, %eax
	ret
.Lmcl_lt:
	mov  $-1, %eax
	ret
.Lmcl_gt:
	mov  $1, %eax
	ret

# w_map_hdr(rsi = count) — emit a CBOR map header (major 5) for an arbitrary count via r15.
	.type w_map_hdr, @function
w_map_hdr:
	cmp  $24, %rsi
	jae  .Lwmh_1
	mov  %sil, %al
	or   $0xa0, %al
	mov  %al, (%r15)
	inc  %r15
	ret
.Lwmh_1:
	cmp  $256, %rsi
	jae  .Lwmh_2
	movb $0xb8, (%r15)
	inc  %r15
	mov  %sil, (%r15)
	inc  %r15
	ret
.Lwmh_2:
	movb $0xb9, (%r15)
	inc  %r15
	mov  %si, %ax
	xchg %al, %ah
	mov  %ax, (%r15)
	add  $2, %r15
	ret

# emit_listing — sort listing_ents, build the system/tree/listing entity, send it (200) by
# reusing send_get_ok (which wraps a verbatim entity blob as the response result).
	.type emit_listing, @function
emit_listing:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	call sort_listing
	# ---- listing data {path, count, offset, entries} ----
	lea  b_list_data(%rip), %r15
	mov  $4, %sil
	call w_map
	lea  k_path(%rip), %rdi
	call w_cstr
	mov  g_lprefix_ptr(%rip), %rsi
	mov  g_lprefix_len(%rip), %rdx
	call w_txt
	lea  k_count(%rip), %rdi
	call w_cstr
	mov  listing_n(%rip), %rsi
	call w_uint
	lea  k_offset(%rip), %rdi
	call w_cstr
	xor  %rsi, %rsi
	call w_uint
	lea  k_entries(%rip), %rdi
	call w_cstr
	mov  listing_n(%rip), %rsi
	call w_map_hdr
	xor  %r12, %r12                  # i
.Lel_loop:
	cmp  listing_n(%rip), %r12
	jae  .Lel_donemap
	mov  %r12, %rax
	shl  $5, %rax
	lea  listing_ents(%rip), %r13
	add  %rax, %r13                  # entry
	mov  0(%r13), %rsi
	mov  8(%r13), %rdx
	call w_txt                       # key = segment
	mov  $2, %sil
	call w_map
	lea  k_hash(%rip), %rdi
	call w_cstr
	mov  16(%r13), %rax
	test %rax, %rax
	jz   .Lel_null
	mov  %rax, %rsi
	mov  $33, %rdx
	call w_bstr
	jmp  .Lel_haschild
.Lel_null:
	movb $0xf6, (%r15)               # CBOR null
	inc  %r15
.Lel_haschild:
	lea  k_has_children(%rip), %rdi
	call w_cstr
	mov  24(%r13), %rax
	test %rax, %rax
	jz   .Lel_false
	movb $0xf5, (%r15)               # true
	inc  %r15
	jmp  .Lel_next
.Lel_false:
	movb $0xf4, (%r15)               # false
	inc  %r15
.Lel_next:
	inc  %r12
	jmp  .Lel_loop
.Lel_donemap:
	lea  b_list_data(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14                  # data len
	lea  t_listing(%rip), %rdi
	mov  $19, %rsi
	lea  b_list_data(%rip), %rdx
	mov  %r14, %rcx
	lea  list_data_ch(%rip), %r8
	call ec_content_hash
	# ---- build the listing entity blob, hand to send_get_ok ----
	lea  b_list_env(%rip), %r15
	lea  t_listing(%rip), %rdi
	lea  b_list_data(%rip), %rsi
	mov  %r14, %rdx
	lea  list_data_ch(%rip), %rcx
	call w_entity
	lea  b_list_env(%rip), %rax
	mov  %r15, %rsi
	sub  %rax, %rsi                  # entity len
	lea  b_list_env(%rip), %rdi
	call send_get_ok
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# emit_sorted_included(edi = count, rsi = table ptr) — emit an `included` CBOR map whose
# entries are sorted by their 33-byte key (ECF §4.2 canonical order). Each table entry is
# 40 bytes: [0]=key_ptr [8]=type_cstr [16]=data_ptr [24]=data_len [32]=chash_ptr.
# Emits via the global r15 cursor (w_map/w_bstr/w_entity), so r15 is left as the cursor.
	.type emit_sorted_included, @function
emit_sorted_included:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rsi, %r12                  # table ptr
	movzbl %dil, %r13d               # count
	# ---- bubble sort by 33-byte key ----
	mov  %r13d, %ecx                 # n
.Lesi_outer:
	cmp  $1, %ecx
	jle  .Lesi_sorted
	xor  %ebx, %ebx                  # j = 0
.Lesi_inner:
	mov  %ecx, %eax
	dec  %eax                        # n-1
	cmp  %eax, %ebx
	jae  .Lesi_outer_dec
	mov  %rbx, %rax
	imul $40, %rax
	lea  (%r12,%rax), %r14           # &entry[j]
	mov  0(%r14), %rdi               # key[j]
	mov  40(%r14), %rsi              # key[j+1]
	call mcmp33                      # eax = signed byte diff (clobbers rax,r10,r11 only)
	test %eax, %eax                  # 32-bit test: a negative diff sets bit31, which a
	jle  .Lesi_noswap                # 64-bit test on rax would misread as positive.
	# swap the two 40-byte entries (5 quads)
	mov  0(%r14),  %rax ; mov 40(%r14), %rdx ; mov %rdx, 0(%r14)  ; mov %rax, 40(%r14)
	mov  8(%r14),  %rax ; mov 48(%r14), %rdx ; mov %rdx, 8(%r14)  ; mov %rax, 48(%r14)
	mov  16(%r14), %rax ; mov 56(%r14), %rdx ; mov %rdx, 16(%r14) ; mov %rax, 56(%r14)
	mov  24(%r14), %rax ; mov 64(%r14), %rdx ; mov %rdx, 24(%r14) ; mov %rax, 64(%r14)
	mov  32(%r14), %rax ; mov 72(%r14), %rdx ; mov %rdx, 32(%r14) ; mov %rax, 72(%r14)
.Lesi_noswap:
	inc  %ebx
	jmp  .Lesi_inner
.Lesi_outer_dec:
	dec  %ecx
	jmp  .Lesi_outer
.Lesi_sorted:
	# ---- emit map(count) then each entry ----
	mov  %r13b, %sil
	call w_map
	xor  %ebx, %ebx                  # i = 0
.Lesi_emit:
	cmp  %r13d, %ebx
	jae  .Lesi_done
	mov  %rbx, %rax
	imul $40, %rax
	lea  (%r12,%rax), %r14           # &entry[i]
	mov  0(%r14), %rsi               # key ptr
	mov  $33, %rdx
	call w_bstr
	mov  8(%r14), %rdi               # type cstr
	mov  16(%r14), %rsi              # data ptr
	mov  24(%r14), %rdx              # data len
	mov  32(%r14), %rcx              # chash ptr
	call w_entity
	inc  %ebx
	jmp  .Lesi_emit
.Lesi_done:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# check_hello_negotiation(rdi = exec data map) -> rax = 1 if the hello was rejected (a 400
# was sent), else 0. Rejects when params.data.hash_formats excludes "ecfv1-sha256" or
# params.data.key_types excludes "ed25519" (§4.5). Absent fields are not rejected (the
# happy path advertises our sets); this only fires on an explicit disjoint advertisement.
	.type check_hello_negotiation, @function
check_hello_negotiation:
	push %rbx
	push %r12
	push %r13                        # 3 pushes (odd) → 16B-align calls into send_error/FFI
	mov  %rdi, %r12                  # exec data map
	# params = map_find(exec, "params", 6)
	lea  k_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhn_ok
	# pdata = map_find(params, "data", 4)
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhn_ok
	mov  %rax, %rbx                  # pdata
	# hash_formats present? require "ecfv1-sha256"
	mov  %rbx, %rdi
	lea  k_hfmts(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhn_kt                     # absent → skip (don't reject)
	mov  %rax, %rdi
	lea  v_ecfv1(%rip), %rsi
	mov  $12, %rdx
	call array_contains
	test %rax, %rax
	jnz  .Lhn_kt
	mov  $400, %rdi
	lea  ec_incompat_hf(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lhn_ret
.Lhn_kt:
	# key_types present? require "ed25519"
	mov  %rbx, %rdi
	lea  k_ktypes(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhn_pid                    # absent → still classify the peer_id's key-type
	mov  %rax, %rdi
	lea  v_ed25519(%rip), %rsi
	mov  $7, %rdx
	call array_contains
	test %rax, %rax
	jnz  .Lhn_pid
	mov  $400, %rdi
	lea  ec_unsup_kt(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lhn_ret
.Lhn_pid:
	# §4.4/§7.1 agility: the hello's peer_id encodes its key-type as a multihash varint
	# prefix. Parse it; anything but ed25519 (key_type 1) — or an unparseable id — is an
	# unsupported algorithm → 400 unsupported_key_type (AGILITY-UNKNOWN-1, key_type 0xFD).
	mov  %rbx, %rdi                  # pdata
	lea  k_peerid(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lhn_ok                     # no peer_id → nothing to classify
	mov  %rax, %rdi
	call get_text                    # rax = ptr, rdx = len
	mov  %rax, %rdi
	mov  %rdx, %rsi
	lea  g_pid_kt(%rip), %rdx
	lea  g_pid_ht(%rip), %rcx
	lea  b_pid_digest(%rip), %r8
	lea  g_pid_dlen(%rip), %r9
	call ec_peerid_parse
	test %eax, %eax
	jnz  .Lhn_bad_kt                 # parse failure → unsupported
	cmpq $1, g_pid_kt(%rip)          # 1 = ed25519 (the core floor)
	je   .Lhn_ok
.Lhn_bad_kt:
	mov  $400, %rdi
	lea  ec_unsup_kt(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lhn_ret
.Lhn_ok:
	xor  %eax, %eax
.Lhn_ret:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# array_contains(rdi = array value ptr, rsi = needle ptr, rdx = needle len) -> rax = 1|0.
# Iterates a CBOR text array; matches by exact bytes. (Elements assumed text — true for
# hash_formats / key_types; a non-text element just won't match.)
	.type array_contains, @function
array_contains:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rsi, %r13                  # needle ptr
	mov  %rdx, %r14                  # needle len
	call read_head                   # rax=after-head, rcx=major(4), rdx=count
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # remaining count
.Lac_l:
	test %rbx, %rbx
	jz   .Lac_no
	mov  %r12, %rdi
	call read_head                   # rax=text start, rdx=len (major 3)
	mov  %rax, %r8                   # element start (survives memeq)
	lea  (%rax,%rdx), %r12           # advance cursor past element text
	cmp  %r14, %rdx
	jne  .Lac_next
	mov  %r13, %rdi
	mov  %r8, %rsi
	mov  %r14, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lac_yes
.Lac_next:
	dec  %rbx
	jmp  .Lac_l
.Lac_yes:
	mov  $1, %eax
	jmp  .Lac_ret
.Lac_no:
	xor  %eax, %eax
.Lac_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# verify_get_auth(rdi = exec data map) -> rax = 0 authorized, 1 rejected (401 sent).
# §5.2 auth-class (401) stage: the request must carry an `author`, that author's system/peer
# entity must be in `included` (→ its public_key), and `included` must hold a system/signature
# with signer=author and target=root.content_hash that Ed25519-verifies over that 33-byte
# hash. A missing author / unresolvable pubkey / absent-or-bad signature → 401
# authentication_failed. (Capability-class 403 checks are a separate, later stage.)
	.type verify_get_auth, @function
verify_get_auth:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 pushes (odd) → 16B-align the send_error/FFI calls
	mov  %rdi, %r15                  # exec data map
	# A. author present?
	mov  %r15, %rdi
	lea  k_author(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	call get_text                    # rax=author ptr, rdx=33
	mov  %rax, %rbx                  # author ptr
	# B. included present?
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %r12                  # included map
	# C. author's peer entity in included → public_key
	mov  %r12, %rdi
	mov  %rbx, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	lea  ka_pubkey(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	call get_text                    # rax=pubkey ptr, rdx=32
	mov  %rax, %r14                  # pubkey ptr
	# D. root.content_hash
	lea  b_req(%rip), %rdi
	lea  k_root(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	lea  k_chash(%rip), %rsi
	mov  $12, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvga_401
	mov  %rax, %rdi
	call get_text                    # rax=root_ch ptr, rdx=33
	mov  %rax, %r13                  # root_ch ptr
	# E. request signature: signer==author, target==root_ch
	mov  %r12, %rdi
	mov  %rbx, %rsi
	mov  %r13, %rdx
	call find_req_sig                # rax = 64-byte signature ptr | 0
	test %rax, %rax
	jz   .Lvga_401
	# F. Ed25519 verify over root_ch
	mov  %r14, %rdi                  # pubkey
	mov  %r13, %rsi                  # message = root_ch
	mov  $33, %rdx
	mov  %rax, %rcx                  # signature
	call ec_ed25519_verify
	test %eax, %eax
	jnz  .Lvga_401
	xor  %eax, %eax                  # authorized
	jmp  .Lvga_ret
.Lvga_401:
	mov  $401, %rdi
	lea  ec_auth_failed(%rip), %rsi
	call send_error
	mov  $1, %eax
.Lvga_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# §5.5a canonicalization + §5.6 attenuation — the delegation-chain interior.
# =====================================================================
#
# peerid_of(rdi = included, rsi = hash33, rdx = out ptr, rcx = out_len ptr) -> rax = 1|0.
# The §5.5a canonicalization FRAME for a link is its granter's peer_id, which is NOT on the
# wire: it is derived from the granter's system/peer entity in `included` — the same entity
# the link's signature is verified against — by re-running the base58 peer-id format over its
# public_key.
	.type peerid_of, @function
peerid_of:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 (odd) → 16B-align the ec_peerid_format call
	mov  %rdx, %r13                  # out
	mov  %rcx, %r14                  # out_len ptr
	call included_find_by_key        # rdi = included, rsi = hash33
	test %rax, %rax
	jz   .Lpio_no
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lpio_no
	mov  %rax, %rdi
	lea  ka_pubkey(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lpio_no
	mov  %rax, %rdi
	call get_text                    # rax = pubkey ptr, rdx = len
	cmp  $32, %rdx
	jne  .Lpio_no
	mov  %rax, %r15
	mov  $1, %edi                    # key_type = ed25519
	xor  %esi, %esi                  # hash_type = 0 (identity)
	mov  %r15, %rdx
	mov  $32, %rcx
	mov  %r13, %r8
	mov  $128, %r9
	sub  $16, %rsp                   # arg7 at [rsp] + 8 pad, alignment preserved
	mov  %r14, (%rsp)
	call ec_peerid_format
	add  $16, %rsp
	test %eax, %eax
	jnz  .Lpio_no
	mov  $1, %eax
	jmp  .Lpio_ret
.Lpio_no:
	xor  %eax, %eax
.Lpio_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# canon(rdi = pattern, rsi = len, rdx = frame, rcx = frame len, r8 = out) -> rax = out len.
# §5.5a: a leading "/" means the pattern already names a peer position — copy verbatim;
# anything else is peer-RELATIVE and becomes "/" + frame + "/" + pattern.
# Bare "*" gets NO special case and deliberately must not: it falls out of the general rule
# as "/{frame}/*", which is exactly what §5.5a says it means — the granter's own namespace,
# never a universal cross-peer wildcard. Special-casing it is how the bare-star-is-universal
# defect (A-PD-017, and swift/sql's frame over-scoping) gets built.
	.type canon, @function
canon:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # pattern
	mov  %rsi, %r13                  # pattern len
	mov  %rdx, %r14                  # frame
	mov  %rcx, %r15                  # frame len
	mov  %r8,  %rbx                  # out
	test %r13, %r13
	jz   .Lcn_rel
	cmpb $0x2f, (%r12)
	jne  .Lcn_rel
	mov  %rbx, %rdi
	mov  %r12, %rsi
	mov  %r13, %rdx
	call mcpy
	mov  %r13, %rax
	jmp  .Lcn_ret
.Lcn_rel:
	movb $0x2f, (%rbx)
	lea  1(%rbx), %rdi
	mov  %r14, %rsi
	mov  %r15, %rdx
	call mcpy                        # rax = dst + frame len
	movb $0x2f, (%rax)
	lea  1(%rax), %rdi
	mov  %r12, %rsi
	mov  %r13, %rdx
	call mcpy
	sub  %rbx, %rax                  # total canonical length
.Lcn_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# pat_covers(rdi = child pat, rsi = child len, rdx = parent pat, rcx = parent len) -> rax=1|0.
# Both canonical, both absolute. Segment-wise:
#   parent "*" as the LAST segment → covers everything remaining
#   parent "*" mid-pattern         → covers exactly one child segment, whatever it is
#   parent literal                 → the child segment must be that literal; a child "*" here
#                                    is BROADER than the parent and is refused
# Both exhausted together → covered; either alone → not covered.
	.type pat_covers, @function
pat_covers:
	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $40, %rsp                   # [0]=ps [8]=pl [16]=cs [24]=cl  (+8 pad → 16B-aligned)
	mov  %rdi, %r12                  # child ptr
	mov  %rsi, %r13                  # child len
	mov  %rdx, %r14                  # parent ptr
	mov  %rcx, %r15                  # parent len
	test %r13, %r13
	jz   .Lpc_no
	test %r15, %r15
	jz   .Lpc_no
	cmpb $0x2f, (%r12)
	jne  .Lpc_no
	cmpb $0x2f, (%r14)
	jne  .Lpc_no
	mov  $1, %rbx                    # ci
	mov  $1, %rbp                    # pi
.Lpc_loop:
	cmp  %r15, %rbp
	jb   .Lpc_pseg
	cmp  %r13, %rbx                  # parent exhausted → covered iff child is too
	jae  .Lpc_yes
	jmp  .Lpc_no
.Lpc_pseg:
	# Read the PARENT segment BEFORE testing whether the child is exhausted: a trailing "*"
	# covers the remainder INCLUDING the empty one. "/{peer}/*" authorizes that peer's
	# namespace, and listing the namespace's own root ("/{peer}/") is inside it, not above
	# it. Testing child-exhaustion first refuses every root listing while every deeper path
	# still works, which reads as a permissions bug rather than a matcher bug.
	lea  (%r14,%rbp), %rax
	mov  %rax, (%rsp)                # ps
	xor  %rcx, %rcx                  # pl
.Lpc_pscan:
	lea  (%rbp,%rcx), %rax
	cmp  %r15, %rax
	jae  .Lpc_pdone
	mov  (%rsp), %rdx
	cmpb $0x2f, (%rdx,%rcx)
	je   .Lpc_pdone
	inc  %rcx
	jmp  .Lpc_pscan
.Lpc_pdone:
	mov  %rcx, 8(%rsp)               # pl
	cmp  $1, %rcx
	jne  .Lpc_child
	mov  (%rsp), %rdx
	cmpb $0x2a, (%rdx)
	jne  .Lpc_child
	lea  (%rbp,%rcx), %rax
	cmp  %r15, %rax
	jae  .Lpc_yes                    # trailing "*" — covers the rest, empty included
.Lpc_child:
	cmp  %r13, %rbx
	jae  .Lpc_no                     # child exhausted under a non-trailing-star parent
	lea  (%r12,%rbx), %rax
	mov  %rax, 16(%rsp)              # cs
	xor  %rcx, %rcx                  # cl
.Lpc_cscan:
	lea  (%rbx,%rcx), %rax
	cmp  %r13, %rax
	jae  .Lpc_cdone
	mov  16(%rsp), %rdx
	cmpb $0x2f, (%rdx,%rcx)
	je   .Lpc_cdone
	inc  %rcx
	jmp  .Lpc_cscan
.Lpc_cdone:
	mov  %rcx, 24(%rsp)              # cl
	cmpq $1, 8(%rsp)
	jne  .Lpc_literal
	mov  (%rsp), %rdx
	cmpb $0x2a, (%rdx)
	je   .Lpc_advance                # mid-pattern "*" — matches this one child segment
.Lpc_literal:
	cmpq $1, 24(%rsp)
	jne  .Lpc_cmp
	mov  16(%rsp), %rdx
	cmpb $0x2a, (%rdx)
	je   .Lpc_no                     # a "*" child under a literal parent is BROADER
.Lpc_cmp:
	mov  24(%rsp), %rax
	cmp  8(%rsp), %rax
	jne  .Lpc_no
	mov  16(%rsp), %rdi
	mov  (%rsp), %rsi
	mov  %rax, %rcx
	call memeq
	test %rax, %rax
	jz   .Lpc_no
.Lpc_advance:
	mov  24(%rsp), %rax
	lea  1(%rbx,%rax), %rbx
	mov  8(%rsp), %rax
	lea  1(%rbp,%rax), %rbp
	jmp  .Lpc_loop
.Lpc_yes:
	mov  $1, %eax
	jmp  .Lpc_ret
.Lpc_no:
	xor  %eax, %eax
.Lpc_ret:
	add  $40, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbp
	pop  %rbx
	ret

# arr_subset_framed(rdi = sub array, rsi = super array) -> rax = 1 if every element of `sub`
# is covered by some element of `super` under §5.5a framing. The two sides canonicalize
# against DIFFERENT frames — g_sfr_ptr/len for `sub`, g_qfr_ptr/len for `super` — which the
# caller sets, so the exclude direction reverses them without copying a frame.
	.type arr_subset_framed, @function
arr_subset_framed:
	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $40, %rsp                   # [0]=sub cursor [8]=sub n [16]=super array [24]=clen
	mov  %rsi, 16(%rsp)
	call read_head                   # rdi = sub array
	cmp  $4, %rcx
	jne  .Lasf_no
	mov  %rax, (%rsp)
	mov  %rdx, 8(%rsp)
.Lasf_outer:
	cmpq $0, 8(%rsp)
	jz   .Lasf_yes
	mov  (%rsp), %rdi
	call read_head                   # rax = elem bytes, rdx = elem len
	mov  %rax, %r12
	mov  %rdx, %r13
	lea  (%rax,%rdx), %rax
	mov  %rax, (%rsp)
	decq 8(%rsp)
	mov  %r12, %rdi
	mov  %r13, %rsi
	mov  g_sfr_ptr(%rip), %rdx
	mov  g_sfr_len(%rip), %rcx
	lea  b_canon_a(%rip), %r8
	call canon
	mov  %rax, 24(%rsp)              # canonical child length
	mov  16(%rsp), %rdi
	call read_head
	cmp  $4, %rcx
	jne  .Lasf_no
	mov  %rax, %r14                  # super cursor
	mov  %rdx, %r15                  # super remaining
.Lasf_inner:
	test %r15, %r15
	jz   .Lasf_no                    # no super element covers this sub element
	mov  %r14, %rdi
	call read_head
	mov  %rax, %rbx
	mov  %rdx, %rbp
	lea  (%rax,%rdx), %r14
	dec  %r15
	mov  %rbx, %rdi
	mov  %rbp, %rsi
	mov  g_qfr_ptr(%rip), %rdx
	mov  g_qfr_len(%rip), %rcx
	lea  b_canon_b(%rip), %r8
	call canon
	mov  %rax, %rcx
	lea  b_canon_a(%rip), %rdi
	mov  24(%rsp), %rsi
	lea  b_canon_b(%rip), %rdx
	call pat_covers
	test %rax, %rax
	jnz  .Lasf_outer
	jmp  .Lasf_inner
.Lasf_yes:
	mov  $1, %eax
	jmp  .Lasf_ret
.Lasf_no:
	xor  %eax, %eax
.Lasf_ret:
	add  $40, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbp
	pop  %rbx
	ret

# dim_subset(rdi = child scope map, rsi = parent scope map, rdx = framed) -> rax = 1|0.
# One scope dimension, child ⊆ parent. `framed` selects §5.5a canonicalization, which scopes
# the RESOURCE dimension ONLY — handlers/operations/peers are id-scope and take no frame.
# Over-applying the frame is the swift/sql defect: a universal parent grant stops covering
# any child grant the moment the two have different granters, and every delegated cap 403s.
# Both halves of the spec's scope_subset are here: child includes covered by parent includes,
# AND every parent exclude inherited by some child exclude.
	.type dim_subset, @function
dim_subset:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %rbx                  # child scope
	mov  %rsi, %r12                  # parent scope
	mov  %rdx, %r13                  # framed
	mov  %rbx, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lds_no
	mov  %rax, %r14                  # child include
	mov  %r12, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lds_no
	mov  %rax, %r15                  # parent include
	test %r13, %r13
	jz   .Lds_inc_plain
	call set_frames_cp               # sub ← child frame, super ← parent frame
	mov  %r14, %rdi
	mov  %r15, %rsi
	call arr_subset_framed
	jmp  .Lds_inc_done
.Lds_inc_plain:
	mov  %r14, %rdi
	mov  %r15, %rsi
	call array_subset_star
.Lds_inc_done:
	test %rax, %rax
	jz   .Lds_no
	# Exclude inheritance runs in the REVERSE direction from includes: each PARENT exclude
	# must be covered by some CHILD exclude, because the child must exclude at least as much
	# as its parent did. A child that simply drops the parent's exclude widens itself.
	mov  %r12, %rdi
	lea  ka_exclude(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lds_yes                    # parent excludes nothing → nothing to inherit
	mov  %rax, %r15                  # parent exclude
	mov  %rbx, %rdi
	lea  ka_exclude(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lds_no                     # parent excluded, child does not → widened
	mov  %rax, %r14                  # child exclude
	test %r13, %r13
	jz   .Lds_exc_plain
	call set_frames_pc               # sub ← parent frame, super ← child frame
	mov  %r15, %rdi
	mov  %r14, %rsi
	call arr_subset_framed
	jmp  .Lds_ret
.Lds_exc_plain:
	mov  %r15, %rdi
	mov  %r14, %rsi
	call array_subset_star
	jmp  .Lds_ret
.Lds_yes:
	mov  $1, %eax
	jmp  .Lds_ret
.Lds_no:
	xor  %eax, %eax
.Lds_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# set_frames_cp / set_frames_pc — point the sub/super frame pair at the child/parent frames
# in the given order. Clobbers rax only.
	.type set_frames_cp, @function
set_frames_cp:
	lea  g_cfr(%rip), %rax
	mov  %rax, g_sfr_ptr(%rip)
	mov  g_cfrlen(%rip), %rax
	mov  %rax, g_sfr_len(%rip)
	lea  g_pfr(%rip), %rax
	mov  %rax, g_qfr_ptr(%rip)
	mov  g_pfrlen(%rip), %rax
	mov  %rax, g_qfr_len(%rip)
	ret
	.type set_frames_pc, @function
set_frames_pc:
	lea  g_pfr(%rip), %rax
	mov  %rax, g_sfr_ptr(%rip)
	mov  g_pfrlen(%rip), %rax
	mov  %rax, g_sfr_len(%rip)
	lea  g_cfr(%rip), %rax
	mov  %rax, g_qfr_ptr(%rip)
	mov  g_cfrlen(%rip), %rax
	mov  %rax, g_qfr_len(%rip)
	ret

# map_attenuated(rdi = from map | 0, rsi = to map | 0) -> rax = 1|0.
# Every key of `from` must appear in `to` with a byte-identical value. Used twice, in
# opposite directions: CONSTRAINTS (every parent key must survive on the child — a dropped
# key widens it) and ALLOWANCES (every child key must already exist on the parent — an added
# key widens it). Absent `from` → vacuously attenuated.
	.type map_attenuated, @function
map_attenuated:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $16, %rsp                   # [0] = child value length
	test %rdi, %rdi
	jz   .Lma_yes
	mov  %rsi, %r15                  # to
	call read_head                   # rdi = from
	cmp  $5, %rcx
	jne  .Lma_no
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # pair count
	test %rbx, %rbx
	jz   .Lma_yes
	test %r15, %r15
	jz   .Lma_no
.Lma_loop:
	test %rbx, %rbx
	jz   .Lma_yes
	mov  %r12, %rdi
	call read_head                   # rax = key bytes, rdx = key len
	mov  %rax, %r13
	mov  %rdx, %r14
	lea  (%rax,%rdx), %r12           # value ptr
	mov  %r15, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	call map_find
	test %rax, %rax
	jz   .Lma_no
	mov  %rax, %r13                  # the counterpart value
	mov  %r12, %rdi
	call skip_value
	mov  %rax, %r14                  # next pair
	sub  %r12, %rax
	mov  %rax, (%rsp)                # this value's byte length
	mov  %r13, %rdi
	call skip_value
	sub  %r13, %rax
	cmp  (%rsp), %rax
	jne  .Lma_no
	mov  %r12, %rdi
	mov  %r13, %rsi
	mov  %rax, %rcx
	call memeq
	test %rax, %rax
	jz   .Lma_no
	mov  %r14, %r12
	dec  %rbx
	jmp  .Lma_loop
.Lma_yes:
	mov  $1, %eax
	jmp  .Lma_ret
.Lma_no:
	xor  %eax, %eax
.Lma_ret:
	add  $16, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# grant_subset_framed(rdi = child grant, rsi = parent grant) -> rax = 1|0.
# All four §5.6 scope dimensions plus constraints and allowances. Only RESOURCES is framed.
	.type grant_subset_framed, @function
grant_subset_framed:
	push %rbx
	push %r12
	push %r13
	mov  %rdi, %rbx                  # child grant
	mov  %rsi, %r12                  # parent grant
	# handlers — id-scope, no frame
	mov  %rbx, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %rax, %r13
	mov  %r12, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %r13, %rdi
	mov  %rax, %rsi
	xor  %edx, %edx
	call dim_subset
	test %rax, %rax
	jz   .Lgsf_no
	# operations — id-scope, no frame
	mov  %rbx, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %rax, %r13
	mov  %r12, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %r13, %rdi
	mov  %rax, %rsi
	xor  %edx, %edx
	call dim_subset
	test %rax, %rax
	jz   .Lgsf_no
	# resources — THE framed dimension, and the only one
	mov  %rbx, %rdi
	lea  ka_resources(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_peers                 # child names no resources → nothing to bound
	mov  %rax, %r13
	mov  %r12, %rdi
	lea  ka_resources(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %r13, %rdi
	mov  %rax, %rsi
	mov  $1, %edx
	call dim_subset
	test %rax, %rax
	jz   .Lgsf_no
.Lgsf_peers:
	# peers — id-scope; absent defaults to {include:[local_peer_id]} on BOTH sides, so an
	# absent-vs-absent pair is trivially a subset and needs no synthesised map.
	mov  %rbx, %rdi
	lea  ka_peers(%rip), %rsi
	mov  $5, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_maps
	mov  %rax, %r13
	mov  %r12, %rdi
	lea  ka_peers(%rip), %rsi
	mov  $5, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgsf_no
	mov  %r13, %rdi
	mov  %rax, %rsi
	xor  %edx, %edx
	call dim_subset
	test %rax, %rax
	jz   .Lgsf_no
.Lgsf_maps:
	# constraints: every parent key retained on the child, byte-equal
	mov  %r12, %rdi
	lea  ka_constraints(%rip), %rsi
	mov  $11, %rdx
	call map_find
	mov  %rax, %r13
	mov  %rbx, %rdi
	lea  ka_constraints(%rip), %rsi
	mov  $11, %rdx
	call map_find
	mov  %r13, %rdi
	mov  %rax, %rsi
	call map_attenuated
	test %rax, %rax
	jz   .Lgsf_no
	# allowances: every child key pre-existing on the parent, byte-equal
	mov  %rbx, %rdi
	lea  ka_allowances(%rip), %rsi
	mov  $10, %rdx
	call map_find
	mov  %rax, %r13
	mov  %r12, %rdi
	lea  ka_allowances(%rip), %rsi
	mov  $10, %rdx
	call map_find
	mov  %r13, %rdi
	mov  %rax, %rsi
	call map_attenuated
	jmp  .Lgsf_ret
.Lgsf_no:
	xor  %eax, %eax
.Lgsf_ret:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# is_attenuated(rdi = child token data, rsi = parent token data) -> rax = 1|0.
# §5.6 with the per-link §5.5a frames already in g_cfr / g_pfr: every child grant covered by
# some parent grant, then the expiration rule.
	.type is_attenuated, @function
is_attenuated:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $16, %rsp                   # [0] = parent grants array, [8] = child grants remaining
	mov  %rdi, %r14                  # child token data
	mov  %rsi, %r15                  # parent token data
	mov  %r14, %rdi
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lia_no
	mov  %rax, %r12                  # child grants array
	mov  %r15, %rdi
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lia_no
	mov  %rax, (%rsp)
	mov  %r12, %rdi
	call read_head
	cmp  $4, %rcx
	jne  .Lia_no
	mov  %rax, %r12                  # child grant cursor
	mov  %rdx, 8(%rsp)               # child grants remaining
.Lia_child:
	cmpq $0, 8(%rsp)
	jz   .Lia_expiry
	mov  (%rsp), %rdi
	call read_head
	cmp  $4, %rcx
	jne  .Lia_no
	mov  %rax, %rbx                  # parent cursor
	mov  %rdx, %r13                  # parent grants remaining
.Lia_parent:
	test %r13, %r13
	jz   .Lia_no                     # this child grant is covered by no parent grant
	mov  %r12, %rdi
	mov  %rbx, %rsi
	call grant_subset_framed
	test %rax, %rax
	jnz  .Lia_covered
	mov  %rbx, %rdi
	call skip_value
	mov  %rax, %rbx
	dec  %r13
	jmp  .Lia_parent
.Lia_covered:
	mov  %r12, %rdi
	call skip_value
	mov  %rax, %r12
	decq 8(%rsp)
	jmp  .Lia_child
.Lia_expiry:
	# §5.6 expiration, nil-vs-finite: a child with NO expires_at is INFINITE, and infinite
	# exceeds any finite parent. The permissive reading — treat the absent child field as
	# "inherits the parent's" — is the one a reader reaches by accident and is explicitly
	# non-conformant.
	mov  %r15, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lia_yes                    # parent never expires → nothing to bound
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lia_no                     # not a uint64 → unusable, never "absent"
	mov  %rdx, %rbx                  # parent expiry
	mov  %r14, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lia_no                     # infinite child under a finite parent
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lia_no
	cmp  %rbx, %rdx
	ja   .Lia_no
.Lia_yes:
	mov  $1, %eax
	jmp  .Lia_ret
.Lia_no:
	xor  %eax, %eax
.Lia_ret:
	add  $16, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# caveats_ok(rdi = parent token data, rsi = child token data, rdx = depth) -> rax = 1|0.
# §5.5 check_delegation_caveats. An absent block means there is nothing to enforce.
	.type caveats_ok, @function
caveats_ok:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rsi, %r14                  # child token data
	mov  %rdx, %r15                  # depth
	lea  ka_deleg_caveats(%rip), %rsi
	mov  $18, %rdx
	call map_find                    # rdi = parent token data
	test %rax, %rax
	jz   .Lco_yes
	mov  %rax, %r12                  # caveats map
	# no_delegation
	mov  %r12, %rdi
	lea  ka_no_delegation(%rip), %rsi
	mov  $13, %rdx
	call map_find
	test %rax, %rax
	jz   .Lco_depth
	cmpb $0xf5, (%rax)               # CBOR true
	je   .Lco_no
.Lco_depth:
	# max_delegation_depth — denied when depth >= limit
	mov  %r12, %rdi
	lea  ka_max_deleg_depth(%rip), %rsi
	mov  $20, %rdx
	call map_find
	test %rax, %rax
	jz   .Lco_ttl
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lco_no
	cmp  %rdx, %r15
	jae  .Lco_no
.Lco_ttl:
	# max_delegation_ttl — an infinite child exceeds any finite limit
	mov  %r12, %rdi
	lea  ka_max_deleg_ttl(%rip), %rsi
	mov  $18, %rdx
	call map_find
	test %rax, %rax
	jz   .Lco_yes
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lco_no
	mov  %rdx, %rbx                  # limit
	mov  %r14, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lco_no                     # child never expires → unbounded ttl
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lco_no
	mov  %rdx, %r13                  # child expires_at
	mov  %r14, %rdi
	lea  ka_created(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lco_no
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Lco_no
	cmp  %rdx, %r13
	jb   .Lco_yes                    # already expired at birth — bounded by anything
	sub  %rdx, %r13
	cmp  %rbx, %r13
	ja   .Lco_no
.Lco_yes:
	mov  $1, %eax
	jmp  .Lco_ret
.Lco_no:
	xor  %eax, %eax
.Lco_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# link_temporal_ok(rdi = token data) -> rax = 1|0, against g_now (§5.5 `t`, sampled once).
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
	push %rbx
	push %r12
	mov  %rdi, %r12
	lea  ka_created(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Llt_nb
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Llt_no
.Llt_nb:
	mov  %r12, %rdi
	lea  ka_notbefore(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Llt_exp
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Llt_no
	cmp  %rdx, g_now(%rip)
	jb   .Llt_no                     # now < not_before
.Llt_exp:
	mov  %r12, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Llt_yes
	mov  %rax, %rdi
	call read_head
	test %rcx, %rcx
	jnz  .Llt_no
	# §5.6 CAP-6: expiry is an EXCLUSIVE upper bound — expired when now >= expires_at. This
	# pairs with ttl_ms:0 minting expires_at == created_at, which must be expired at every
	# observable instant rather than valid for one and racing.
	cmp  %rdx, g_now(%rip)
	jae  .Llt_no
.Llt_yes:
	mov  $1, %eax
	jmp  .Llt_ret
.Llt_no:
	xor  %eax, %eax
.Llt_ret:
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# verify_get_cap(rdi = exec data map) -> rax = 0 authorized, 1 rejected (403/401 sent).
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
# verify_multisig_granter(rdi = granter map, rsi = cap_hash ptr, rdx = included) -> rax = 0
# accept / 1 reject. §5.5 M3/M4/M6: threshold ≥ 2, N ≥ 2, 2 ≤ threshold ≤ N, parent null,
# signers distinct, THIS peer ∈ signers, and ≥ threshold distinct signers each hold a valid
# Ed25519 signature over the token hash. Fail-closed on any structural miss.
	.type verify_multisig_granter, @function
verify_multisig_granter:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5
	mov  %rsi, %r13                  # cap_hash
	mov  %rdx, %r12                  # included
	mov  %rdi, %rbx                  # granter map
	# threshold
	lea  ka_threshold(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvms_reject
	mov  %rax, %rdi
	call read_head                   # rdx = threshold
	mov  %rdx, g_ms_thresh(%rip)
	cmp  $2, %rdx
	jb   .Lvms_reject                # threshold < 2
	# (M3's root-only rule is enforced by the caller, against the TOKEN's `parent` field —
	# testing the GRANTER map for a `parent` key is vacuous, since {signers, threshold}
	# never carries one.)
	# signers array
	mov  %rbx, %rdi
	lea  ka_signers(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvms_reject
	mov  %rax, %rdi
	call read_head                   # rax=first elem, rcx=major, rdx=count
	cmp  $4, %rcx
	jne  .Lvms_reject
	mov  %rdx, %r15                  # N
	mov  %rax, %r14                  # signer cursor
	cmp  $2, %r15
	jb   .Lvms_reject                # N < 2
	cmp  $32, %r15
	ja   .Lvms_reject                # bound the scratch array
	mov  g_ms_thresh(%rip), %rax
	cmp  %r15, %rax
	ja   .Lvms_reject                # threshold > N
	# collect signer-hash pointers into g_ms_sigs[0..N)
	xor  %rbx, %rbx                  # i
.Lvms_collect:
	cmp  %r15, %rbx
	jae  .Lvms_collected
	mov  %r14, %rdi
	call get_text                    # rax = signer ptr (33)
	lea  g_ms_sigs(%rip), %rcx
	mov  %rax, (%rcx,%rbx,8)
	mov  %r14, %rdi
	call skip_value
	mov  %rax, %r14
	inc  %rbx
	jmp  .Lvms_collect
.Lvms_collected:
	# distinctness — reject if any two signers are equal
	xor  %rbx, %rbx                  # i
.Lvms_di:
	cmp  %r15, %rbx
	jae  .Lvms_distinct_ok
	lea  1(%rbx), %r14               # j = i+1
.Lvms_dj:
	cmp  %r15, %r14
	jae  .Lvms_di_next
	lea  g_ms_sigs(%rip), %rcx
	mov  (%rcx,%rbx,8), %rdi
	mov  (%rcx,%r14,8), %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lvms_reject                # duplicate signer
	inc  %r14
	jmp  .Lvms_dj
.Lvms_di_next:
	inc  %rbx
	jmp  .Lvms_di
.Lvms_distinct_ok:
	movq $0, g_ms_valid(%rip)
	movq $0, g_ms_local(%rip)
	xor  %rbx, %rbx                  # i
.Lvms_vloop:
	cmp  %r15, %rbx
	jae  .Lvms_counted
	lea  g_ms_sigs(%rip), %rcx
	mov  (%rcx,%rbx,8), %r14         # signer i ptr
	# local ∈ signers?
	mov  %r14, %rdi
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lvms_notlocal
	movq $1, g_ms_local(%rip)
.Lvms_notlocal:
	# a valid signature by signer i over cap_hash?
	mov  %r12, %rdi
	mov  %r14, %rsi
	mov  %r13, %rdx
	call find_req_sig                # rax = 64-byte sig ptr | 0
	test %rax, %rax
	jz   .Lvms_vnext
	mov  %rax, g_ms_sigptr(%rip)
	# signer i public_key from its system/peer in included
	mov  %r12, %rdi
	mov  %r14, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvms_vnext
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvms_vnext
	mov  %rax, %rdi
	lea  ka_pubkey(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvms_vnext
	mov  %rax, %rdi
	call get_text                    # rax = pubkey ptr
	mov  %rax, %rdi
	mov  %r13, %rsi
	mov  $33, %rdx
	mov  g_ms_sigptr(%rip), %rcx
	call ec_ed25519_verify
	test %eax, %eax
	jnz  .Lvms_vnext                 # invalid signature
	incq g_ms_valid(%rip)
.Lvms_vnext:
	inc  %rbx
	jmp  .Lvms_vloop
.Lvms_counted:
	cmpq $0, g_ms_local(%rip)
	je   .Lvms_reject                # THIS peer must be a co-signer
	mov  g_ms_valid(%rip), %rax
	cmp  g_ms_thresh(%rip), %rax
	jb   .Lvms_reject                # fewer than threshold valid signatures
	xor  %eax, %eax                  # accept
	jmp  .Lvms_ret
.Lvms_reject:
	mov  $1, %eax
.Lvms_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

	.type verify_get_cap, @function
verify_get_cap:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 pushes (odd) → align send_error/FFI calls
	sub  $48, %rsp                   # [0]=included [8]=author [16]=cur hash [24]=depth [32]=ctd
	mov  %rdi, %r15                  # exec data map
	# capability present?
	mov  %r15, %rdi
	lea  k_capability(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	call get_text                    # rax = cap_hash ptr (33)
	cmp  $33, %rdx
	jne  .Lvgc_403
	mov  %rax, 16(%rsp)              # cur = the presented capability hash
	# author (verify_get_auth already ensured present)
	mov  %r15, %rdi
	lea  k_author(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	call get_text
	mov  %rax, 8(%rsp)               # author ptr
	# included
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, (%rsp)                # included
	movq $0, 24(%rsp)                # depth
	movq $0, 32(%rsp)                # child token data (none yet)
	# §5.5 v7.76: `t` is sampled ONCE per verdict and never re-sampled per link — otherwise
	# the verdict depends on wall-clock drift within a single walk.
	call now_ms
	mov  %rax, g_now(%rip)
# ---------------------------------------------------------------- the walk
.Lvgc_walk:
	mov  (%rsp), %rdi
	mov  16(%rsp), %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvgc_403                   # capability_not_in_included
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %r12                  # td — this link's token data map
	# integrity: the link's data must hash to the hash we followed to reach it. A token whose
	# bytes were altered after signing no longer hashes to its key → 403.
	mov  %r12, %rdi
	call skip_value
	sub  %r12, %rax                  # data byte length
	lea  ta_token(%rip), %rdi
	mov  $23, %rsi
	mov  %r12, %rdx
	mov  %rax, %rcx
	lea  g_link_ch(%rip), %r8
	call ec_content_hash
	lea  g_link_ch(%rip), %rdi
	mov  16(%rsp), %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lvgc_403                   # recomputed hash ≠ the key we followed → substituted
	# §6.9a — revocation is PER LINK: revoking an intermediate kills everything under it.
	mov  16(%rsp), %rdi
	call is_revoked
	test %rax, %rax
	jnz  .Lvgc_403
	# grantee present, 33 bytes, and resolving to a present system/peer — per link, not just
	# at the leaf. An unresolvable grantee is the §5.2 / PR-3 single-401 carve-out, NOT 403.
	mov  %r12, %rdi
	lea  ka_grantee(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	call get_text
	cmp  $33, %rdx
	jne  .Lvgc_403
	mov  %rax, %r13                  # grantee ptr
	mov  (%rsp), %rdi
	mov  %r13, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvgc_grantee_401
	mov  %rax, %rdi
	lea  k_type(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_grantee_401
	mov  %rax, %rdi
	call get_text
	cmp  $11, %rdx
	jne  .Lvgc_grantee_401
	mov  %rax, %rdi
	lea  ta_peer(%rip), %rsi
	mov  $11, %rcx
	call memeq
	test %rax, %rax
	jz   .Lvgc_grantee_401
	# linkage: the LEAF is granted to the request author; every parent is granted to the
	# granter of the link below it (g_pgee carries that hash across the hop).
	mov  %r13, %rdi
	cmpq $0, 24(%rsp)
	jne  .Lvgc_link_parent
	mov  8(%rsp), %rsi               # author
	jmp  .Lvgc_link_cmp
.Lvgc_link_parent:
	lea  g_pgee(%rip), %rsi
.Lvgc_link_cmp:
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lvgc_403                   # grantee_author_mismatch / broken chain linkage
	# temporal validity of THIS link (CAP-6a representability first)
	mov  %r12, %rdi
	call link_temporal_ok
	test %rax, %rax
	jz   .Lvgc_403
	# granter
	mov  %r12, %rdi
	lea  ka_granter(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %r13                  # granter value ptr
	mov  %r13, %rdi
	call read_head                   # rcx = major type
	cmp  $5, %rcx
	jne  .Lvgc_single_granter
	# §3.6 K-of-N multi-granter. M3 structural validity runs BEFORE any signature check, so a
	# violation surfaces as 403 capability_denied rather than as a signature failure.
	# Multi-sig is ROOT-ONLY: a multi-granter link carrying a parent is structurally invalid.
	mov  %r12, %rdi
	lea  ka_parent(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_ms_root
	cmpb $0xf6, (%rax)               # CBOR null is "no parent"
	jne  .Lvgc_403
.Lvgc_ms_root:
	# A quorum root has no single granter peer_id, so §5.5a has no frame to canonicalize its
	# resource patterns against. Rather than invent one, a K-of-N root is accepted only when
	# it is the capability actually PRESENTED (depth 0), where no attenuation comparison is
	# needed. A chain whose ROOT is K-of-N is refused, and that limit is written here rather
	# than left to be discovered.
	cmpq $0, 24(%rsp)
	jne  .Lvgc_403
	mov  %r13, %rdi
	mov  16(%rsp), %rsi
	mov  (%rsp), %rdx
	call verify_multisig_granter
	test %rax, %rax
	jnz  .Lvgc_403
	jmp  .Lvgc_ok                    # quorum met — the chain terminates here
.Lvgc_single_granter:
	mov  %r13, %rdi
	call get_text
	cmp  $33, %rdx
	jne  .Lvgc_403
	mov  %rax, %r13                  # granter hash
	# signature over THIS link, by THIS link's granter
	mov  (%rsp), %rdi
	mov  %r13, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	lea  ka_pubkey(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_403
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r14                  # granter pubkey (survives find_req_sig)
	mov  (%rsp), %rdi
	mov  %r13, %rsi
	mov  16(%rsp), %rdx
	call find_req_sig                # rax = 64-byte sig ptr | 0
	test %rax, %rax
	jz   .Lvgc_403                   # unsigned / forged
	mov  %r14, %rdi
	mov  16(%rsp), %rsi
	mov  $33, %rdx
	mov  %rax, %rcx
	call ec_ed25519_verify
	test %eax, %eax
	jnz  .Lvgc_403
	# this link's §5.5a frame = its granter's peer_id
	mov  (%rsp), %rdi
	mov  %r13, %rsi
	lea  g_pfr(%rip), %rdx
	lea  g_pfrlen(%rip), %rcx
	call peerid_of
	test %rax, %rax
	jz   .Lvgc_403
	# attenuation + caveats against the child we arrived from
	cmpq $0, 24(%rsp)
	je   .Lvgc_rootcheck
	mov  32(%rsp), %rdi              # ctd
	mov  %r12, %rsi
	call is_attenuated
	test %rax, %rax
	jz   .Lvgc_403
	mov  %r12, %rdi
	mov  32(%rsp), %rsi
	mov  24(%rsp), %rdx
	dec  %rdx
	call caveats_ok
	test %rax, %rax
	jz   .Lvgc_403
.Lvgc_rootcheck:
	mov  %r12, %rdi
	lea  ka_parent(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgc_root
	cmpb $0xf6, (%rax)               # an explicit null parent is a root
	je   .Lvgc_root
	mov  %rax, %r14                  # parent hash value ptr
	# carry the child state across the hop: its data, its granter, and its frame
	mov  %r12, 32(%rsp)              # ctd = this link
	lea  g_pgee(%rip), %rdi
	mov  %r13, %rsi
	mov  $33, %rdx
	call mcpy
	lea  g_cfr(%rip), %rdi
	lea  g_pfr(%rip), %rsi
	mov  $128, %rdx
	call mcpy
	mov  g_pfrlen(%rip), %rax
	mov  %rax, g_cfrlen(%rip)
	mov  %r14, %rdi
	call get_text
	cmp  $33, %rdx
	jne  .Lvgc_403
	mov  %rax, 16(%rsp)              # cur = parent
	incq 24(%rsp)
	# §5.5 collect_authority_chain bounds depth at 64. chain_depth_check already answers 400
	# chain_depth_exceeded ahead of this walk, so this is the belt to that braces — it exists
	# so the loop cannot run unbounded if the walk is ever reached by another path.
	cmpq $64, 24(%rsp)
	ja   .Lvgc_403
	jmp  .Lvgc_walk
.Lvgc_root:
	# §5.5 root trust: the chain must terminate at a capability THIS peer granted. The check
	# has not gone away — it is here, at the end of the walk, instead of standing in for it.
	mov  %r13, %rdi
	lea  g_identity_hash(%rip), %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lvgc_403
.Lvgc_ok:
	xor  %eax, %eax                  # authorized
	jmp  .Lvgc_ret
.Lvgc_403:
	mov  $403, %rdi
	lea  ec_cap_denied(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lvgc_ret
.Lvgc_grantee_401:
	mov  $401, %rdi
	lea  ec_unresolvable_grantee(%rip), %rsi
	call send_error
	mov  $1, %eax
.Lvgc_ret:
	add  $48, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# is_peer_id(rdi = ptr, rsi = len) -> rax = 1 if len >= 46 and every byte is in the Base58
# alphabet (§5.4 is_peer_id: Base58(key_type||hash_type||digest), 46 chars is the minimum
# for the smallest supported algorithm — Ed25519+SHA-256), else 0. Used by extract_peer
# (derive_handler below) to decide whether a uri's first path segment is a real peer id.
	.globl is_peer_id
	.type is_peer_id, @function
is_peer_id:
	cmp  $46, %rsi
	jb   .Lipi_no
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rdi, %r12                  # ptr
	mov  %rsi, %r13                  # len
	xor  %r14d, %r14d                # i
.Lipi_loop:
	cmp  %r13, %r14
	jae  .Lipi_yes
	movzbl (%r12,%r14), %ebx
	lea  s_base58_alpha(%rip), %rdx
	xor  %eax, %eax
.Lipi_scan:
	cmp  $58, %eax
	jae  .Lipi_no_pop
	cmpb %bl, (%rdx,%rax)
	je   .Lipi_found
	inc  %eax
	jmp  .Lipi_scan
.Lipi_found:
	inc  %r14
	jmp  .Lipi_loop
.Lipi_no_pop:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	xor  %eax, %eax
	ret
.Lipi_yes:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	mov  $1, %eax
	ret
.Lipi_no:
	xor  %eax, %eax
	ret

# =====================================================================
# derive_handler(rdi = exec data map) — set g_handler_ptr/g_handler_len to the request's
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
	push %rbx
	push %r12
	push %r13
	push %r14
	lea  va_systree(%rip), %rax       # default handler = system/tree
	mov  %rax, g_handler_ptr(%rip)
	movq $11, g_handler_len(%rip)
	lea  g_peerid(%rip), %rax         # default target_peer = local peer id
	mov  %rax, g_target_peer_ptr(%rip)
	mov  g_peerid_len(%rip), %rax
	mov  %rax, g_target_peer_len(%rip)
	lea  k_uri(%rip), %rsi
	mov  $3, %rdx
	call map_find                     # rdi = exec (preserved)
	test %rax, %rax
	jz   .Ldh_ret
	mov  %rax, %rdi
	call get_text                     # rax = uri ptr, rdx = uri len
	mov  %rax, %r12
	mov  %rdx, %r13
	cmp  $9, %r13                     # "entity://" = 9 bytes
	jb   .Ldh_ret
	mov  %r12, %rdi
	lea  s_entity_scheme(%rip), %rsi
	mov  $9, %rcx
	call memeq
	test %rax, %rax
	jz   .Ldh_ret
	lea  9(%r12), %rbx                # cursor past the scheme
	mov  %rbx, %r14                   # first-segment start (candidate target_peer)
	mov  %r13, %r12
	sub  $9, %r12                     # remaining len (the "<peer>/<handler>" authority+path)
.Ldh_scan:
	test %r12, %r12
	jz   .Ldh_ret                     # no '/', keep defaults (handler + target_peer)
	cmpb $0x2f, (%rbx)
	je   .Ldh_found
	inc  %rbx
	dec  %r12
	jmp  .Ldh_scan
.Ldh_found:
	# candidate peer-id segment = [r14, rbx) — validate before adopting it as target_peer
	# (extract_peer only trusts a first segment that is_peer_id).
	mov  %rbx, %rax
	sub  %r14, %rax                   # segment length
	mov  %r14, %rdi
	mov  %rax, %rsi
	call is_peer_id
	test %rax, %rax
	jz   .Ldh_not_peer
	mov  %r14, g_target_peer_ptr(%rip)
	mov  %rbx, %rax
	sub  %r14, %rax
	mov  %rax, g_target_peer_len(%rip)
.Ldh_not_peer:
	inc  %rbx                         # skip the '/'
	dec  %r12
	mov  %rbx, g_handler_ptr(%rip)
	mov  %r12, g_handler_len(%rip)
.Ldh_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# verify_get_scope(rdi = exec data map) -> rax = 0 authorized, 1 rejected (403 sent).
# §5.2 grant-scope stage, after verify_get_cap: the presented token must carry a grant that
# permits (operation, handler [from uri], resource-target). No matching grant → 403
# capability_denied (default-deny).
	.type verify_get_scope, @function
verify_get_scope:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 (odd) → align send_error
	mov  %rdi, %r15                  # exec
	# derive the request's handler namespace from data.uri (→ g_handler_ptr/len).
	call derive_handler              # rdi = exec
	# capability → token → token data map
	mov  %r15, %rdi
	lea  k_capability(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_ok                   # (verify_get_cap already enforced presence)
	mov  %rax, %rdi
	call get_text
	mov  %rax, %rbx                  # cap hash
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_ok
	mov  %rax, %rdi
	mov  %rbx, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvgsc_ok
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_ok
	mov  %rax, %r14                  # token data map
	# ---- §5.5a frame for the DISPATCH surface: the presented cap's own granter ----
	# Derived here rather than assumed to be the local peer — they are byte-identical for
	# every self-issued capability, which is exactly why framing against the verifier stays
	# latent until a foreign-granted cap arrives.
	mov  %r14, %rdi
	lea  ka_granter(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_403
	mov  %rax, %r12
	mov  %r12, %rdi
	call read_head
	cmp  $5, %rcx
	jne  .Lvgsc_single_frame
	# §3.6 K-of-N root: there is no single granter, so §5.5a has no granter peer_id to frame
	# against. The local peer is the CORRECT frame here and not a fallback — M6 already
	# required that the local peer be in the signer set AND have signed, and §5.5 says a
	# quorum cap's "subsequent use is locally rooted". The quorum authorized issuance; the
	# namespace its patterns name is this peer's.
	lea  g_dfr(%rip), %rdi
	lea  g_peerid(%rip), %rsi
	mov  g_peerid_len(%rip), %rdx
	mov  %rdx, g_dfrlen(%rip)
	call mcpy
	jmp  .Lvgsc_frame_ok
.Lvgsc_single_frame:
	mov  %r12, %rdi
	call get_text
	mov  %rax, %r12                  # granter hash
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_403
	mov  %rax, %rdi
	mov  %r12, %rsi
	lea  g_dfr(%rip), %rdx
	lea  g_dfrlen(%rip), %rcx
	call peerid_of
	test %rax, %rax
	jz   .Lvgsc_403
.Lvgsc_frame_ok:
	# ---- token temporal validity (only fires if the fields are present) ----
	call now_ms                      # rax = wall-clock ms
	mov  %rax, %r12                  # now
	# expires_at present and now > it → expired
	mov  %r14, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_nb
	mov  %rax, %rdi
	call read_head                   # rdx = expires_at (uint ms)
	cmp  %rdx, %r12
	ja   .Lvgsc_403                  # now > expires_at
.Lvgsc_nb:
	# not_before present and now < it → not yet valid
	mov  %r14, %rdi
	lea  ka_notbefore(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_temporal_ok
	mov  %rax, %rdi
	call read_head                   # rdx = not_before (uint ms)
	cmp  %rdx, %r12
	jb   .Lvgsc_403                  # now < not_before
.Lvgsc_temporal_ok:
	# operation
	mov  %r15, %rdi
	lea  k_op(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_403
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r12                  # op ptr
	mov  %rdx, %r13                  # op len
	# target = resource.targets[0]
	mov  %r15, %rdi
	lea  k_resource(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_403
	mov  %rax, %rdi
	lea  k_targets(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvgsc_403
	mov  %rax, %rdi
	call read_head                   # array head: rdx=count
	test %rdx, %rdx
	jz   .Lvgsc_403
	mov  %rax, %rdi
	call get_text                    # rax=target ptr, rdx=target len
	# grant_scope_ok(token_data, target ptr, target len, op ptr, op len)
	mov  %r14, %rdi
	mov  %rax, %rsi
	mov  %r12, %rcx
	mov  %r13, %r8
	call grant_scope_ok
	test %rax, %rax
	jnz  .Lvgsc_ok
.Lvgsc_403:
	mov  $403, %rdi
	lea  ec_cap_denied(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lvgsc_ret
.Lvgsc_ok:
	xor  %eax, %eax
.Lvgsc_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# =====================================================================
# grant_scope_ok(rdi=token data map, rsi=target ptr, rdx=target len, rcx=op ptr, r8=op len)
#   -> rax = 1 if some grant permits (operation ∈ operations.include) ∧ (handler ∈
#      handlers.include) ∧ (target matches resources.include), else 0. "*" wildcards honored.
# The handler is g_handler_ptr/len, parsed from data.uri by derive_handler.
	.globl grant_scope_ok
	.type grant_scope_ok, @function
grant_scope_ok:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	push %rbp
	mov  %rsi, %r13                  # target ptr
	mov  %rdx, %r14                  # target len
	mov  %rcx, %r15                  # op ptr
	mov  %r8,  %rbp                  # op len
	# grants = map_find(token_data, "grants", 6)
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_no
	mov  %rax, %rdi
	call read_head                   # rax=first elem, rcx=4, rdx=count
	mov  %rax, %r12                  # cursor (grant map ptr)
	mov  %rdx, %rbx                  # grant count
.Lgs_loop:
	test %rbx, %rbx
	jz   .Lgs_no
	# operations.include ∋ op ?
	mov  %r12, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	mov  %r15, %rsi
	mov  %rbp, %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Lgs_next
	# handlers.include ∋ system/tree ?
	mov  %r12, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	mov  g_handler_ptr(%rip), %rsi   # request handler (parsed from data.uri)
	mov  g_handler_len(%rip), %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Lgs_next
	# peers.include ∋ target_peer ? (§5.2/F-peers) grant.peers defaults to
	# {include:[local_peer_id]} when the grant omits the field entirely.
	mov  %r12, %rdi
	lea  ka_peers(%rip), %rsi
	mov  $5, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_peers_default
	mov  %rax, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_peers_default
	mov  %rax, %rdi
	mov  g_target_peer_ptr(%rip), %rsi
	mov  g_target_peer_len(%rip), %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Lgs_next
	jmp  .Lgs_peers_ok
.Lgs_peers_default:
	mov  g_target_peer_len(%rip), %rax
	cmp  g_peerid_len(%rip), %rax
	jne  .Lgs_next
	mov  g_target_peer_ptr(%rip), %rdi
	lea  g_peerid(%rip), %rsi
	mov  %rax, %rcx
	call memeq
	test %rax, %rax
	jz   .Lgs_next
.Lgs_peers_ok:
	# resources.include matches target ?
	mov  %r12, %rdi
	lea  ka_resources(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgs_next
	mov  %rax, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	call resources_cover_target
	test %rax, %rax
	jnz  .Lgs_yes
.Lgs_next:
	mov  %r12, %rdi
	call skip_value                  # advance past this grant map
	mov  %rax, %r12
	dec  %rbx
	jmp  .Lgs_loop
.Lgs_yes:
	mov  $1, %eax
	jmp  .Lgs_ret
.Lgs_no:
	xor  %eax, %eax
.Lgs_ret:
	pop  %rbp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# op_scope_ok(rdi = token data, rsi = op ptr, rdx = op len) -> rax = 1 if some grant permits
# (operation ∈ operations.include) ∧ (handler ∈ handlers.include) ∧ (target peer ∈ peers).
# The RESOURCE dimension is absent by construction: these are the capability-vocabulary ops
# that carry no resource.targets, so there is no target to match and asking for one would
# deny every one of them.
	.type op_scope_ok, @function
op_scope_ok:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rsi, %r14                  # op ptr
	mov  %rdx, %r15                  # op len
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Los_no
	mov  %rax, %rdi
	call read_head
	cmp  $4, %rcx
	jne  .Los_no
	mov  %rax, %r12                  # grant cursor
	mov  %rdx, %rbx                  # grant count
.Los_loop:
	test %rbx, %rbx
	jz   .Los_no
	mov  %r12, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call get_include
	test %rax, %rax
	jz   .Los_next
	mov  %rax, %rdi
	mov  %r14, %rsi
	mov  %r15, %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Los_next
	mov  %r12, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call get_include
	test %rax, %rax
	jz   .Los_next
	mov  %rax, %rdi
	mov  g_handler_ptr(%rip), %rsi
	mov  g_handler_len(%rip), %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Los_next
	mov  %r12, %rdi
	lea  ka_peers(%rip), %rsi
	mov  $5, %rdx
	call get_include
	test %rax, %rax
	jz   .Los_peers_default
	mov  %rax, %rdi
	mov  g_target_peer_ptr(%rip), %rsi
	mov  g_target_peer_len(%rip), %rdx
	call array_contains_star
	test %rax, %rax
	jz   .Los_next
	jmp  .Los_yes
.Los_peers_default:
	mov  g_target_peer_len(%rip), %rax
	cmp  g_peerid_len(%rip), %rax
	jne  .Los_next
	mov  g_target_peer_ptr(%rip), %rdi
	lea  g_peerid(%rip), %rsi
	mov  %rax, %rcx
	call memeq
	test %rax, %rax
	jz   .Los_next
	jmp  .Los_yes
.Los_next:
	mov  %r12, %rdi
	call skip_value
	mov  %rax, %r12
	dec  %rbx
	jmp  .Los_loop
.Los_yes:
	mov  $1, %eax
	jmp  .Los_ret
.Los_no:
	xor  %eax, %eax
.Los_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# verify_op_scope(rdi = exec data map) -> rax = 0 authorized, 1 rejected (403 sent).
# §5.2 operation-scope gate for a capability-vocabulary op with no resource.targets. Without
# it a peer that authenticates a caller then routes straight into the handler never asks
# whether the presented capability covers this op on this handler at all — and a floor cap
# (capability:request only) would reach configure/revoke unchecked.
	.type verify_op_scope, @function
verify_op_scope:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15                        # 5 (odd) → align send_error
	mov  %rdi, %r15                  # exec
	call derive_handler              # rdi = exec (→ g_handler_ptr/len, g_target_peer_*)
	mov  %r15, %rdi
	lea  k_capability(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_403
	mov  %rax, %rdi
	call get_text
	mov  %rax, %rbx                  # cap hash
	lea  b_req(%rip), %rdi
	lea  ka_included(%rip), %rsi
	mov  $8, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_403
	mov  %rax, %rdi
	mov  %rbx, %rsi
	call included_find_by_key
	test %rax, %rax
	jz   .Lvos_403
	mov  %rax, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_403
	mov  %rax, %r14                  # token data
	call now_ms
	mov  %rax, %r12                  # now
	mov  %r14, %rdi
	lea  ka_expires(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_nb
	mov  %rax, %rdi
	call read_head
	cmp  %rdx, %r12
	ja   .Lvos_403                   # now > expires_at
.Lvos_nb:
	mov  %r14, %rdi
	lea  ka_notbefore(%rip), %rsi
	mov  $10, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_op
	mov  %rax, %rdi
	call read_head
	cmp  %rdx, %r12
	jb   .Lvos_403                   # now < not_before
.Lvos_op:
	mov  %r15, %rdi
	lea  k_op(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lvos_403
	mov  %rax, %rdi
	call get_text
	mov  %rax, %r12
	mov  %rdx, %r13
	mov  %r14, %rdi
	mov  %r12, %rsi
	mov  %r13, %rdx
	call op_scope_ok
	test %rax, %rax
	jnz  .Lvos_ok
.Lvos_403:
	mov  $403, %rdi
	lea  ec_cap_denied(%rip), %rsi
	call send_error
	mov  $1, %eax
	jmp  .Lvos_ret
.Lvos_ok:
	xor  %eax, %eax
.Lvos_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# array_contains_star(rdi=array, rsi=needle, rdx=needle len) -> rax = 1 if the array
# contains the needle OR a bare "*". Reuses array_contains twice.
	.type array_contains_star, @function
array_contains_star:
	push %rbx
	push %r12
	push %r13
	push %r14                        # even count OK — no FFI/send below
	mov  %rdi, %r12                  # array
	mov  %rsi, %r13                  # needle
	mov  %rdx, %r14                  # needle len
	call array_contains              # (rdi=array, rsi=needle, rdx=len)
	test %rax, %rax
	jnz  .Lacs_yes
	mov  %r12, %rdi
	lea  s_star(%rip), %rsi
	mov  $1, %rdx
	call array_contains
	test %rax, %rax
	jnz  .Lacs_yes
	xor  %eax, %eax
	jmp  .Lacs_ret
.Lacs_yes:
	mov  $1, %eax
.Lacs_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# resources_cover_target(rdi = resources.include array, rsi = target ptr, rdx = target len)
#   -> rax = 1 if some pattern covers the request target under §5.5a.
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
	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $40, %rsp                   # [0] = canonical target length
	mov  %rdi, %r12                  # include array
	mov  %rsi, %rdi
	mov  %rdx, %rsi
	lea  g_peerid(%rip), %rdx
	mov  g_peerid_len(%rip), %rcx
	lea  b_canon_a(%rip), %r8
	call canon
	mov  %rax, (%rsp)
	mov  %r12, %rdi
	call read_head
	cmp  $4, %rcx
	jne  .Lrct_no
	mov  %rax, %r14                  # pattern cursor
	mov  %rdx, %r15                  # remaining
.Lrct_loop:
	test %r15, %r15
	jz   .Lrct_no
	mov  %r14, %rdi
	call read_head                   # rax = pattern bytes, rdx = len
	mov  %rax, %rbx
	mov  %rdx, %rbp
	lea  (%rax,%rdx), %r14
	dec  %r15
	mov  %rbx, %rdi
	mov  %rbp, %rsi
	lea  g_dfr(%rip), %rdx
	mov  g_dfrlen(%rip), %rcx
	lea  b_canon_b(%rip), %r8
	call canon
	mov  %rax, %rcx
	lea  b_canon_a(%rip), %rdi
	mov  (%rsp), %rsi
	lea  b_canon_b(%rip), %rdx
	call pat_covers
	test %rax, %rax
	jz   .Lrct_loop
	mov  $1, %eax
	jmp  .Lrct_ret
.Lrct_no:
	xor  %eax, %eax
.Lrct_ret:
	add  $40, %rsp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbp
	pop  %rbx
	ret

# resource_matches(rdi=include array, rsi=target ptr, rdx=target len) -> rax = 1 if any
# pattern matches. Patterns: bare "*" (any); trailing "/*" (prefix match on everything up to
# and including the slash); otherwise an exact match. Used for the §6.2 mint-time subset,
# where both sides are the LOCAL peer's and no frame translation applies.
	.type resource_matches, @function
resource_matches:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	push %rbp
	mov  %rsi, %r13                  # target ptr
	mov  %rdx, %r14                  # target len
	call read_head                   # rdi=array → rax=first elem, rdx=count
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # pattern count
.Lrm_l:
	test %rbx, %rbx
	jz   .Lrm_no
	mov  %r12, %rdi
	call read_head                   # pattern text: rax=ptr, rdx=len
	mov  %rax, %r15                  # pattern ptr
	mov  %rdx, %rbp                  # pattern len
	lea  (%rax,%rdx), %r12           # advance cursor past pattern
	dec  %rbx
	# case bare "*"
	cmp  $1, %rbp
	jne  .Lrm_check_suffix
	cmpb $0x2a, (%r15)
	je   .Lrm_yes
	jmp  .Lrm_l
.Lrm_check_suffix:
	# trailing "/*" ? (plen>=2 and last two bytes are '/','*')
	cmp  $2, %rbp
	jb   .Lrm_exact
	mov  %rbp, %rax
	cmpb $0x2a, -1(%r15,%rax)
	jne  .Lrm_exact
	cmpb $0x2f, -2(%r15,%rax)
	jne  .Lrm_exact
	# prefix = pattern[0 .. plen-1] (through the slash, i.e. plen-1 bytes); target must be
	# at least that long and share the prefix bytes.
	mov  %rbp, %rcx
	dec  %rcx                        # prefix len (keep the '/')
	cmp  %rcx, %r14
	jb   .Lrm_l                      # target shorter than prefix → no match
	mov  %r15, %rdi
	mov  %r13, %rsi
	call memeq                       # rcx = prefix len
	test %rax, %rax
	jnz  .Lrm_yes
	jmp  .Lrm_l
.Lrm_exact:
	cmp  %rbp, %r14
	jne  .Lrm_l
	mov  %r15, %rdi
	mov  %r13, %rsi
	mov  %rbp, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lrm_yes
	jmp  .Lrm_l
.Lrm_yes:
	mov  $1, %eax
	jmp  .Lrm_ret
.Lrm_no:
	xor  %eax, %eax
.Lrm_ret:
	pop  %rbp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# get_include(rdi = grant map, rsi = field cstr, rdx = field len) -> rax = <field>.include
# array value ptr | 0.  grant[field]["include"].
	.type get_include, @function
get_include:
	push %rbx
	call map_find
	test %rax, %rax
	jz   .Lgi_no
	mov  %rax, %rdi
	lea  ka_include(%rip), %rsi
	mov  $7, %rdx
	call map_find
	test %rax, %rax
	jz   .Lgi_no
	pop  %rbx
	ret
.Lgi_no:
	xor  %eax, %eax
	pop  %rbx
	ret

# array_subset_star(rdi = req array value, rsi = caller array value) -> rax = 1 if every
# text element of req appears in caller (a bare "*" in caller matches any element). An empty
# req array is a vacuous subset (1).
	.type array_subset_star, @function
array_subset_star:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rsi, %r15                  # caller array value
	call read_head                   # rdi = req array → rax=first elem, rdx=count
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # remaining count
.Lss_loop:
	test %rbx, %rbx
	jz   .Lss_yes
	mov  %r12, %rdi
	call read_head                   # element text: rax=ptr, rdx=len
	mov  %rax, %r13                  # elem ptr
	mov  %rdx, %r14                  # elem len
	lea  (%rax,%rdx), %r12           # advance cursor past this element
	dec  %rbx
	mov  %r15, %rdi                  # caller array
	mov  %r13, %rsi
	mov  %r14, %rdx
	call array_contains_star
	test %rax, %rax
	jnz  .Lss_loop                   # covered → next req element
	xor  %eax, %eax                  # some element not covered → not a subset
	jmp  .Lss_ret
.Lss_yes:
	mov  $1, %eax
.Lss_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# resources_subset(rdi = req resources.include, rsi = caller resources.include) -> rax = 1 if
# every req resource is matched by a caller pattern (resource_matches: "*", trailing "/*",
# exact). Empty req → 1.
	.type resources_subset, @function
resources_subset:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rsi, %r15                  # caller resources array
	call read_head                   # rdi = req array → rax=first, rdx=count
	mov  %rax, %r12
	mov  %rdx, %rbx
.Lrs_loop:
	test %rbx, %rbx
	jz   .Lrs_yes
	mov  %r12, %rdi
	call read_head                   # req resource text: rax=ptr, rdx=len
	mov  %rax, %r13
	mov  %rdx, %r14
	lea  (%rax,%rdx), %r12
	dec  %rbx
	mov  %r15, %rdi                  # caller resources array
	mov  %r13, %rsi
	mov  %r14, %rdx
	call resource_matches
	test %rax, %rax
	jnz  .Lrs_loop
	xor  %eax, %eax
	jmp  .Lrs_ret
.Lrs_yes:
	mov  $1, %eax
.Lrs_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# grant_covers(rdi = caller grant map, rsi = req grant map) -> rax = 1 if the caller grant
# authorizes everything the req grant asks for: req.operations ⊆ caller.operations,
# req.handlers ⊆ caller.handlers, req.resources all matched by caller.resources.
	.type grant_covers, @function
grant_covers:
	push %rbx
	push %r12
	push %r13                        # 3 (odd)
	mov  %rdi, %r12                  # caller grant
	mov  %rsi, %r13                  # req grant
	# operations
	mov  %r13, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_no                     # req without operations.include → treat as uncoverable
	mov  %rax, %rbx                  # req.ops
	mov  %r12, %rdi
	lea  ka_operations(%rip), %rsi
	mov  $10, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_no
	mov  %rbx, %rdi
	mov  %rax, %rsi
	call array_subset_star
	test %rax, %rax
	jz   .Lgc_no
	# handlers
	mov  %r13, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_no
	mov  %rax, %rbx
	mov  %r12, %rdi
	lea  ka_handlers(%rip), %rsi
	mov  $8, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_no
	mov  %rbx, %rdi
	mov  %rax, %rsi
	call array_subset_star
	test %rax, %rax
	jz   .Lgc_no
	# resources (req resources ⊆ caller resources by pattern match); absent req resources → ok
	mov  %r13, %rdi
	lea  ka_resources(%rip), %rsi
	mov  $9, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_yes                    # no resources requested → nothing to bound
	mov  %rax, %rbx
	mov  %r12, %rdi
	lea  ka_resources(%rip), %rsi
	mov  $9, %rdx
	call get_include
	test %rax, %rax
	jz   .Lgc_no                     # req asks resources but caller grant has none
	mov  %rbx, %rdi
	mov  %rax, %rsi
	call resources_subset
	test %rax, %rax
	jz   .Lgc_no
.Lgc_yes:
	mov  $1, %eax
	jmp  .Lgc_ret
.Lgc_no:
	xor  %eax, %eax
.Lgc_ret:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# grants_attenuated(rdi = requested grants array value, rsi = caller token data map) ->
# rax = 1 if every requested grant is covered by some caller grant (i.e. the request does
# not widen scope beyond the caller's authority). Empty requested set → 1.
	.type grants_attenuated, @function
grants_attenuated:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rsi, %r15                  # caller token data
	call read_head                   # rdi = req grants → rax=first, rdx=count
	mov  %rax, %r13                  # req cursor
	mov  %rdx, %r14                  # req count
.Lga_req:
	test %r14, %r14
	jz   .Lga_yes
	mov  %r13, %rbx                  # this requested grant map
	# walk the caller grants, seeking one that covers this requested grant
	mov  %r15, %rdi
	lea  ka_grants(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lga_no
	mov  %rax, %rdi
	call read_head                   # caller grants → rax=first, rdx=count
	mov  %rax, %r12                  # caller cursor
	push %r14
	mov  %rdx, %r14                  # caller count (reuse r14 within inner loop)
.Lga_caller:
	test %r14, %r14
	jz   .Lga_uncovered
	mov  %r12, %rdi
	mov  %rbx, %rsi
	call grant_covers
	test %rax, %rax
	jnz  .Lga_covered
	mov  %r12, %rdi
	call skip_value
	mov  %rax, %r12
	dec  %r14
	jmp  .Lga_caller
.Lga_uncovered:
	pop  %r14
	jmp  .Lga_no
.Lga_covered:
	pop  %r14                        # restore outer req count
	# advance req cursor past this grant
	mov  %r13, %rdi
	call skip_value
	mov  %rax, %r13
	dec  %r14
	jmp  .Lga_req
.Lga_yes:
	mov  $1, %eax
	jmp  .Lga_ret
.Lga_no:
	xor  %eax, %eax
.Lga_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# included_find_by_key(rdi = included map, rsi = key33 ptr) -> rax = value entity ptr | 0.
# `included` is keyed by 33-byte content hashes; returns the value whose key bytes match.
	.type included_find_by_key, @function
included_find_by_key:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rsi, %r13                  # key
	call read_head                   # rdi=included → rax=after, rcx=5, rdx=count
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # remaining pairs
.Lifk_l:
	test %rbx, %rbx
	jz   .Lifk_no
	mov  %r12, %rdi
	call read_head                   # key bstr: rax=bytes, rdx=len
	mov  %rax, %r14                  # key bytes
	lea  (%rax,%rdx), %r12           # cursor → value
	cmp  $33, %rdx
	jne  .Lifk_skipval
	mov  %r14, %rdi
	mov  %r13, %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lifk_found
.Lifk_skipval:
	mov  %r12, %rdi
	call skip_value                  # skip value entity
	mov  %rax, %r12
	dec  %rbx
	jmp  .Lifk_l
.Lifk_found:
	mov  %r12, %rax                  # value ptr (cursor sits at value)
	jmp  .Lifk_ret
.Lifk_no:
	xor  %eax, %eax
.Lifk_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# find_req_sig(rdi = included map, rsi = author33, rdx = root_ch33) -> rax = 64-byte
# signature ptr | 0. Scans `included` for a system/signature with signer==author and
# target==root_ch. (Pure reader — no FFI — so 16B alignment is irrelevant here.)
	.type find_req_sig, @function
find_req_sig:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	push %rbp
	mov  %rsi, %r13                  # author
	mov  %rdx, %r14                  # root_ch
	call read_head                   # rdi=included → rax=after, rdx=count
	mov  %rax, %r12                  # cursor
	mov  %rdx, %rbx                  # remaining pairs
.Lfrs_l:
	test %rbx, %rbx
	jz   .Lfrs_no
	mov  %r12, %rdi
	call read_head                   # key bstr: rax=bytes, rdx=len
	lea  (%rax,%rdx), %r15           # value entity ptr
	mov  %r15, %rdi
	call skip_value                  # advance cursor to next pair NOW
	mov  %rax, %r12
	dec  %rbx
	# value.type == "system/signature"?
	mov  %r15, %rdi
	lea  k_type(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfrs_l
	mov  %rax, %rdi
	call get_text
	cmp  $16, %rdx
	jne  .Lfrs_l
	mov  %rax, %rdi
	lea  ta_sig(%rip), %rsi
	mov  $16, %rcx
	call memeq
	test %rax, %rax
	jz   .Lfrs_l
	# data map
	mov  %r15, %rdi
	lea  k_data(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfrs_l
	mov  %rax, %rbp                  # sig data map
	# signer == author?
	mov  %rbp, %rdi
	lea  ka_signer(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfrs_l
	mov  %rax, %rdi
	call get_text
	cmp  $33, %rdx
	jne  .Lfrs_l
	mov  %rax, %rdi
	mov  %r13, %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lfrs_l
	# target == root_ch?
	mov  %rbp, %rdi
	lea  ka_target(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfrs_l
	mov  %rax, %rdi
	call get_text
	cmp  $33, %rdx
	jne  .Lfrs_l
	mov  %rax, %rdi
	mov  %r14, %rsi
	mov  $33, %rcx
	call memeq
	test %rax, %rax
	jz   .Lfrs_l
	# match → return signature bytes (64)
	mov  %rbp, %rdi
	lea  ka_sig(%rip), %rsi
	mov  $9, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfrs_l
	mov  %rax, %rdi
	call get_text                    # rax = sig ptr, rdx = 64
	jmp  .Lfrs_ret
.Lfrs_no:
	xor  %eax, %eax
.Lfrs_ret:
	pop  %rbp
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# mcmp33(rdi=a, rsi=b) -> rax = a[i]-b[i] at first differing byte over 33 bytes (0 if equal).
# Sign gives bytewise order. Clobbers only rax, r10, r11.
	.type mcmp33, @function
mcmp33:
	xor  %r10d, %r10d
.Lmc_l:
	cmp  $33, %r10d
	jae  .Lmc_eq
	movzbl (%rdi,%r10), %eax
	movzbl (%rsi,%r10), %r11d
	sub  %r11d, %eax
	jnz  .Lmc_ret
	inc  %r10d
	jmp  .Lmc_l
.Lmc_eq:
	xor  %eax, %eax
.Lmc_ret:
	ret

# find_sig_entity(rdi=included map ptr) -> rax = the system/signature entity ptr | 0
	.type find_sig_entity, @function
find_sig_entity:
	push %rbx
	push %r12
	push %r13
	call read_head                   # rax=cursor, rdx=count
	mov  %rax, %r12
	mov  %rdx, %rbx
.Lfse_loop:
	test %rbx, %rbx
	jz   .Lfse_none
	mov  %r12, %rdi
	call skip_value                  # skip key (33-byte hash)
	mov  %rax, %r12
	mov  %r12, %r13                  # value entity ptr
	mov  %r13, %rdi
	lea  k_type(%rip), %rsi
	mov  $4, %rdx
	call map_find
	test %rax, %rax
	jz   .Lfse_skipval
	mov  %rax, %rdi
	call get_text
	cmp  $16, %rdx
	jne  .Lfse_skipval
	mov  %rax, %rdi
	lea  ta_sig(%rip), %rsi
	mov  $16, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lfse_found
.Lfse_skipval:
	mov  %r13, %rdi
	call skip_value
	mov  %rax, %r12
	dec  %rbx
	jmp  .Lfse_loop
.Lfse_found:
	mov  %r13, %rax
	jmp  .Lfse_ret
.Lfse_none:
	xor  %eax, %eax
.Lfse_ret:
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# build_echo_response(rdi = exec data map) — system/validate/echo: return the params
# entity verbatim as the result (the §6.11(b) request_id round-trip probe).
	.type build_echo_response, @function
build_echo_response:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	# params entity ptr + byte length
	lea  ka_params(%rip), %rsi
	mov  $6, %rdx
	call map_find
	test %rax, %rax
	jz   .Lecho_ret
	mov  %rax, %r12                  # params entity ptr
	mov  %rax, %rdi
	call skip_value
	sub  %r12, %rax
	mov  %rax, %r13                  # params entity byte length
	# resp data {result: <params entity raw>, status:200, request_id}
	lea  b_ar_resp(%rip), %r15
	mov  $3, %sil
	call w_map
	lea  k_result(%rip), %rdi
	call w_cstr
	mov  %r12, %rsi
	mov  %r13, %rdx
	call w_raw                       # embed the params entity verbatim
	lea  k_status(%rip), %rdi
	call w_cstr
	mov  $200, %rsi
	call w_uint
	lea  k_rid(%rip), %rdi
	call w_cstr
	mov  g_rid_ptr(%rip), %rsi
	mov  g_rid_len(%rip), %rdx
	call w_txt
	lea  b_ar_resp(%rip), %rax
	mov  %r15, %rdx
	sub  %rax, %rdx
	mov  %rdx, g_ardlen(%rip)
	lea  t_resp(%rip), %rdi
	mov  $32, %rsi
	lea  b_ar_resp(%rip), %rdx
	mov  g_ardlen(%rip), %rcx
	lea  resp_ch2(%rip), %r8
	call ec_content_hash
	# envelope {root: resp}
	lea  b_ar_env(%rip), %r15
	mov  $1, %sil
	call w_map
	lea  k_root(%rip), %rdi
	call w_cstr
	lea  t_resp(%rip), %rdi
	lea  b_ar_resp(%rip), %rsi
	mov  g_ardlen(%rip), %rdx
	lea  resp_ch2(%rip), %rcx
	call w_entity
	lea  b_ar_env(%rip), %rax
	mov  %r15, %r14
	sub  %rax, %r14
	mov  %r14d, %eax
	bswap %eax
	mov  %eax, b_hdr(%rip)
	mov  g_connfd(%rip), %rdi
	lea  b_hdr(%rip), %rsi
	mov  $4, %rdx
	call write_all
	mov  g_connfd(%rip), %rdi
	lea  b_ar_env(%rip), %rsi
	mov  %r14, %rdx
	call write_all
.Lecho_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

	.section .note.GNU-stack,"",@progbits

	.section .note.GNU-stack,"",@progbits

