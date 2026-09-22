;; dispatch.wat — envelope parse + handler dispatch (increment 3, stage 2).
;; STAGE 2 scope: parse the request envelope (root → EXECUTE data map → uri/operation/
;; request_id) and build the connect/hello RESPONSE (the universal entry). Other operations
;; echo for now (temporary) until their handlers land. Response built bottom-up per
;; WIRE-GROUNDTRUTH: result-data(a6) → content_hash → result entity → response-data(a3) →
;; content_hash → response entity → envelope{root}. No `included` for hello (map(1)).
;;
;; Shared-memory conventions (set by host.wat): peer_id text @0x420200, len @0x4202F0.
;; Scratch: 0x900000 result-data, 0x908000 result-entity, 0x910000 response-data,
;; 0x920000 result_ch(33), 0x920040 resp_ch(33), 0x930000 nonce(32), 0x930040 clock(u64).

(module
  (import "codec" "memory" (memory 17))
  (import "codec" "ec_content_hash" (func $content_hash (param i32 i32 i32 i32 i32) (result i32)))
  (import "codec" "ec_ed25519_sign"   (func $ed_sign   (param i32 i32 i32 i32) (result i32)))
  (import "codec" "ec_ed25519_verify" (func $ed_verify (param i32 i32 i32 i32) (result i32)))
  (import "codec" "ec_peerid_parse"    (func $peerid_parse (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "identity" "identity_hash"   (func $identity_hash   (param i32 i32) (result i32)))
  (import "identity" "format_peer_id"  (func $format_peer_id  (param i32 i32 i32 i32) (result i32)))
  (import "identity" "build_peer_data" (func $build_peer_data (param i32 i32) (result i32)))
  (import "wire" "rd_head"  (func $rd_head  (param i32) (result i32)))
  (import "wire" "skip"     (func $skip     (param i32) (result i32)))
  (import "wire" "map_find" (func $map_find (param i32 i32 i32) (result i32)))
  (import "wire" "streq"    (func $streq    (param i32 i32 i32 i32) (result i32)))
  (import "wire" "w_map"    (func $w_map    (param i64)))
  (import "wire" "w_array"  (func $w_array  (param i64)))
  (import "wire" "w_uint"   (func $w_uint   (param i64)))
  (import "wire" "w_text"   (func $w_text   (param i32 i32)))
  (import "wire" "w_bstr"   (func $w_bstr   (param i32 i32)))
  (import "wire" "w_bytes"  (func $w_bytes  (param i32 i32)))
  (import "wire" "g_major"  (global $g_major (mut i32)))
  (import "wire" "g_arg"    (global $g_arg (mut i64)))
  (import "wire" "g_wp"     (global $g_wp  (mut i32)))
  (import "wasi_snapshot_preview1" "random_get"     (func $random_get     (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get" (func $clock_time_get (param i32 i64 i32) (result i32)))

  ;; rodata constants @0x460000 (materialized by $disp_init)
  (data $c_root  "root")          (data $c_data "data")   (data $c_type "type")
  (data $c_chash "content_hash")
  (data $c_respt "system/protocol/execute/response")
  (data $c_hellt "system/protocol/connect/hello")
  (data $c_resul "result")        (data $c_stat "status") (data $c_rid  "request_id")
  (data $c_op    "operation")     (data $c_hello "hello")
  (data $c_nonce "nonce")         (data $c_pid  "peer_id")
  (data $c_ktyp  "key_types")     (data $c_prot "protocols") (data $c_ts "timestamp")
  (data $c_hfmt  "hash_formats")
  (data $c_ed    "ed25519")       (data $c_ecp  "entity-core/1.0") (data $c_ecf "ecfv1-sha256")

  ;; authenticate rodata @0x461000 (slot i = 0x461000 + i*0x40; materialized by $disp_init2)
  (data $a_params  "params")       (data $a_incl   "included")   (data $a_pubk  "public_key")
  (data $a_sigt    "signature")    (data $a_signer "signer")     (data $a_target "target")
  (data $a_algo    "algorithm")    (data $a_grants "grants")     (data $a_grantee "grantee")
  (data $a_granter "granter")      (data $a_created "created_at") (data $a_token "token")
  (data $a_hand    "handlers")     (data $a_res    "resources")  (data $a_ops   "operations")
  (data $a_include "include")      (data $a_code   "code")       (data $a_ktype "key_type")
  (data $a_tauth   "system/protocol/connect/authenticate")
  (data $a_tpeer   "system/peer")  (data $a_tsig   "system/signature")
  (data $a_ttok    "system/capability/token") (data $a_tgrant "system/capability/grant")
  (data $a_terr    "system/protocol/error")   (data $a_ed25519 "ed25519")
  (data $a_vtree   "system/tree")  (data $a_vtype  "system/type/*") (data $a_vhand "system/handler/*")
  (data $a_vget    "get")          (data $a_vcap   "system/capability") (data $a_vreq "request")
  (data $a_einonce "invalid_nonce") (data $a_eafail "authentication_failed")
  (data $a_eimm    "identity_mismatch") (data $a_ekt "unsupported_key_type")
  (data $a_opauth  "authenticate") (data $a_ehnf "handler_not_found")
  (data $a_eihf    "incompatible_hash_format")
  ;; §5.2 peers-scope (id-scope) grant dimension — grant.peers.{include,exclude}
  (data $a_peers   "peers")         (data $a_exclude "exclude")

  ;; tree-GET / authority / store rodata @0x462000 (slot i → 0x462000 + i*0x40; via $disp_init)
  (data $b_author   "author")     (data $b_cap    "capability") (data $b_resource "resource")
  (data $b_targets  "targets")    (data $b_uri    "uri")        (data $b_parent   "parent")
  (data $b_expires  "expires_at") (data $b_notbef "not_before") (data $b_get "get")
  (data $b_capden   "capability_denied") (data $b_chaind "chain_depth_exceeded")
  (data $b_invpath  "invalid_path") (data $b_notfound "not_found") (data $b_unresg "unresolvable_grantee")
  (data $b_paytoobig "payload_too_large")  ;; §4.10(a) 413 code
  (data $b_entity "entity") (data $b_exphash "expected_hash") (data $b_hashmm "hash_mismatch")  ;; §6.3 tree put
  (data $b_scheme   "entity://")   (data $b_star   "*")          (data $b_slashstar "/*")
  ;; store: paths, keys, values, types
  (data $b_pconn "system/handler/system/protocol/connect")
  (data $b_ptree "system/handler/system/tree")
  (data $b_pcapa "system/handler/system/capability")
  (data $b_plist "system/handler/")
  (data $b_name  "name")          (data $b_pattern "pattern")
  (data $b_intype "input_type")   (data $b_outtype "output_type")
  (data $b_tiface "system/handler/interface")
  (data $b_vconn "connect")       (data $b_vtree "tree")        (data $b_vcapa "capability")
  (data $b_scpconn "system/protocol/connect") (data $b_put "put") (data $b_deleg "delegate") (data $b_revoke "revoke")
  (data $b_primany "primitive/any")
  (data $b_tlist "system/tree/listing") (data $b_tlent "system/tree/listing-entry")
  (data $b_entries "entries")     (data $b_path "path")
  (data $b_diff "diff") (data $b_merge "merge") (data $b_extract "extract") (data $b_snapshot "snapshot")
  (data $b_unsupop "unsupported_operation")
  ;; capability write-handler constants (slots 0x462ac0+)
  (data $b_ppolicy "system/capability/policy/")       ;; configure path prefix (25)
  (data $b_prevoc  "system/capability/revocations/")  ;; revoke/is_revoked path prefix (30)
  (data $b_configure "configure")                     ;; op name (9)
  (data $b_invparams "invalid_params")                ;; 400 error code (14)
  (data $b_hexchars  "0123456789abcdef")              ;; hex nibble table (16)
  ;; §6.13a / §10.1 handler register/unregister constants (slots 0x466800+)
  (data $b_thand    "system/handler")                 ;; handler entity type (14)
  (data $b_tregres  "system/handler/register-result") ;; result entity type (30)
  (data $b_grantsp  "system/capability/grants/")       ;; grant path prefix (25)
  (data $b_sigpp    "system/signature/")               ;; signature path prefix (17)
  (data $b_kiface   "interface")                       ;; handler-entity field key (9)
  (data $b_kmanif   "manifest")                         ;; register-request field key (8)
  (data $b_kexpr    "expression_path")                  ;; manifest field key (15)
  (data $b_kintsc   "internal_scope")                   ;; manifest field key (14)
  (data $b_kreqsc   "requested_scope")                  ;; register-request field key (15)
  (data $b_kgrant   "grant")                            ;; register-result field key (5)
  (data $b_register   "register")                       ;; op name (8)
  (data $b_unregister "unregister")                     ;; op name (10)
  (data $b_ambigres "ambiguous_resource")               ;; 400 error code (18)
  (data $b_manifmm  "manifest_pattern_mismatch")        ;; 400 error code (25)
  (data $b_pwild    "/*/*")                              ;; peer-wildcard resource pattern (4)
  (data $b_forbidpat "forbidden_pattern")                ;; §6.2 403 error code (17)
  (data $b_sysexact "system")                            ;; §6.2 reserved pattern exact match (6)
  (data $b_sysslash "system/")                           ;; §6.2 reserved pattern prefix match (7)
  ;; ===== §7a conformance handlers (--validate) — pattern/path/field constants (0x466a00+) =====
  (data $v_pecho  "system/validate/echo")                            ;; echo pattern (20)
  (data $v_pdisp  "system/validate/dispatch-outbound")               ;; dispatch-outbound pattern (33)
  (data $v_hiecho "system/handler/system/validate/echo")             ;; echo interface path (35)
  (data $v_hidisp "system/handler/system/validate/dispatch-outbound");; dispatch-outbound iface path (48)
  (data $v_dispatch "dispatch")                                      ;; op name (8)
  (data $v_echo   "echo")                                            ;; op name / operation value (4)
  (data $v_value  "value")                                           ;; params field (5)
  (data $v_target "target")                                          ;; params field (6)
  (data $v_rcap   "reentry_capability")                              ;; params field (18)
  (data $v_rgrant "reentry_granter")                                 ;; params field (15)
  (data $v_rcsig  "reentry_cap_signature")                           ;; params field (21)
  (data $v_ridpfx "wro-")                                            ;; outbound reentry request_id prefix (4)
  ;; ===== §9.5 Core Type Floor: 53 system/type/* entity constants (slot 0x463000+i*0x40) =====
  (data $t_000 "system/type")
  (data $t_001 "system/type/core/entity")
  (data $t_002 "core/entity")
  (data $t_003 "data")
  (data $t_004 "primitive/any")
  (data $t_005 "type")
  (data $t_006 "primitive/string")
  (data $t_007 "content_hash")
  (data $t_008 "system/hash")
  (data $t_009 "system/type/core/envelope")
  (data $t_00a "core/envelope")
  (data $t_00b "root")
  (data $t_00c "included")
  (data $t_00d "system/type/entity")
  (data $t_00e "entity")
  (data $t_00f "system/type/primitive/any")
  (data $t_010 "system/type/primitive/bool")
  (data $t_011 "primitive/bool")
  (data $t_012 "system/type/primitive/bytes")
  (data $t_013 "primitive/bytes")
  (data $t_014 "system/type/primitive/float")
  (data $t_015 "primitive/float")
  (data $t_016 "system/type/primitive/int")
  (data $t_017 "primitive/int")
  (data $t_018 "system/type/primitive/null")
  (data $t_019 "primitive/null")
  (data $t_01a "system/type/primitive/string")
  (data $t_01b "system/type/primitive/uint")
  (data $t_01c "primitive/uint")
  (data $t_01d "system/type/system/bounds")
  (data $t_01e "system/bounds")
  (data $t_01f "ttl")
  (data $t_020 "budget")
  (data $t_021 "visited")
  (data $t_022 "system/tree/path")
  (data $t_023 "chain_id")
  (data $t_024 "cascade_depth")
  (data $t_025 "parent_chain_id")
  (data $t_026 "system/type/system/capability/delegate-request")
  (data $t_027 "system/capability/delegate-request")
  (data $t_028 "grants")
  (data $t_029 "system/capability/grant-entry")
  (data $t_02a "parent")
  (data $t_02b "ttl_ms")
  (data $t_02c "system/type/system/capability/delegation-caveats")
  (data $t_02d "system/capability/delegation-caveats")
  (data $t_02e "no_delegation")
  (data $t_02f "max_delegation_ttl")
  (data $t_030 "max_delegation_depth")
  (data $t_031 "system/type/system/capability/grant")
  (data $t_032 "system/capability/grant")
  (data $t_033 "token")
  (data $t_034 "system/type/system/capability/grant-entry")
  (data $t_035 "peers")
  (data $t_036 "system/capability/id-scope")
  (data $t_037 "handlers")
  (data $t_038 "system/capability/path-scope")
  (data $t_039 "resources")
  (data $t_03a "allowances")
  (data $t_03b "operations")
  (data $t_03c "constraints")
  (data $t_03d "system/type/system/capability/id-scope")
  (data $t_03e "exclude")
  (data $t_03f "include")
  (data $t_040 "system/type/system/capability/multi-granter")
  (data $t_041 "system/capability/multi-granter")
  (data $t_042 "signers")
  (data $t_043 "threshold")
  (data $t_044 "system/type/system/capability/path-scope")
  (data $t_045 "system/type/system/capability/policy-entry")
  (data $t_046 "system/capability/policy-entry")
  (data $t_047 "notes")
  (data $t_048 "peer_pattern")
  (data $t_049 "system/type/system/capability/request")
  (data $t_04a "system/capability/request")
  (data $t_04b "system/type/system/capability/revocation")
  (data $t_04c "system/capability/revocation")
  (data $t_04d "reason")
  (data $t_04e "revoked_at")
  (data $t_04f "system/type/system/capability/revoke-request")
  (data $t_050 "system/capability/revoke-request")
  (data $t_051 "system/type/system/capability/token")
  (data $t_052 "system/capability/token")
  (data $t_053 "grantee")
  (data $t_054 "granter")
  (data $t_055 "created_at")
  (data $t_056 "expires_at")
  (data $t_057 "not_before")
  (data $t_058 "resource_limits")
  (data $t_059 "system/resource-limits")
  (data $t_05a "delegation_caveats")
  (data $t_05b "system/type/system/deletion-marker")
  (data $t_05c "system/deletion-marker")
  (data $t_05d "system/type/system/delivery-spec")
  (data $t_05e "system/delivery-spec")
  (data $t_05f "uri")
  (data $t_060 "operation")
  (data $t_061 "system/type/system/envelope")
  (data $t_062 "system/envelope")
  (data $t_063 "system/type/system/handler")
  (data $t_064 "system/handler")
  (data $t_065 "interface")
  (data $t_066 "max_scope")
  (data $t_067 "internal_scope")
  (data $t_068 "expression_path")
  (data $t_069 "system/type/system/handler/interface")
  (data $t_06a "system/handler/interface")
  (data $t_06b "name")
  (data $t_06c "pattern")
  (data $t_06d "system/handler/operation-spec")
  (data $t_06e "system/type/system/handler/manifest")
  (data $t_06f "system/handler/manifest")
  (data $t_070 "system/type/system/handler/operation-spec")
  (data $t_071 "input_type")
  (data $t_072 "system/type/name")
  (data $t_073 "output_type")
  (data $t_074 "system/type/system/handler/register-request")
  (data $t_075 "system/handler/register-request")
  (data $t_076 "types")
  (data $t_077 "manifest")
  (data $t_078 "requested_scope")
  (data $t_079 "system/type/system/handler/register-result")
  (data $t_07a "system/handler/register-result")
  (data $t_07b "grant")
  (data $t_07c "system/type/system/hash")
  (data $t_07d "format_code")
  (data $t_07e "digest")
  (data $t_07f "system/type/system/peer")
  (data $t_080 "system/peer")
  (data $t_081 "peer_id")
  (data $t_082 "system/peer-id")
  (data $t_083 "key_type")
  (data $t_084 "public_key")
  (data $t_085 "system/type/system/peer-id")
  (data $t_086 "system/type/system/protocol/connect/authenticate")
  (data $t_087 "system/protocol/connect/authenticate")
  (data $t_088 "nonce")
  (data $t_089 "system/type/system/protocol/connect/hello")
  (data $t_08a "system/protocol/connect/hello")
  (data $t_08b "key_types")
  (data $t_08c "protocols")
  (data $t_08d "timestamp")
  (data $t_08e "encryption")
  (data $t_08f "compression")
  (data $t_090 "hash_formats")
  (data $t_091 "system/type/system/protocol/envelope")
  (data $t_092 "system/protocol/envelope")
  (data $t_093 "system/type/system/protocol/error")
  (data $t_094 "system/protocol/error")
  (data $t_095 "code")
  (data $t_096 "message")
  (data $t_097 "rejected_marker")
  (data $t_098 "system/type/system/protocol/execute")
  (data $t_099 "system/protocol/execute")
  (data $t_09a "author")
  (data $t_09b "bounds")
  (data $t_09c "params")
  (data $t_09d "resource")
  (data $t_09e "system/protocol/resource-target")
  (data $t_09f "capability")
  (data $t_0a0 "deliver_to")
  (data $t_0a1 "request_id")
  (data $t_0a2 "deliver_token")
  (data $t_0a3 "durability_request")
  (data $t_0a4 "system/durability-request")
  (data $t_0a5 "system/type/system/protocol/execute/response")
  (data $t_0a6 "system/protocol/execute/response")
  (data $t_0a7 "result")
  (data $t_0a8 "status")
  (data $t_0a9 "durability")
  (data $t_0aa "system/durability-result")
  (data $t_0ab "system/type/system/protocol/resource-target")
  (data $t_0ac "targets")
  (data $t_0ad "system/type/system/resource-limits")
  (data $t_0ae "max_ttl")
  (data $t_0af "max_budget")
  (data $t_0b0 "max_visited_length")
  (data $t_0b1 "system/type/system/signature")
  (data $t_0b2 "system/signature")
  (data $t_0b3 "signer")
  (data $t_0b4 "target")
  (data $t_0b5 "algorithm")
  (data $t_0b6 "signature")
  (data $t_0b7 "system/type/system/tree/get-request")
  (data $t_0b8 "system/tree/get-request")
  (data $t_0b9 "mode")
  (data $t_0ba "limit")
  (data $t_0bb "offset")
  (data $t_0bc "tree_id")
  (data $t_0bd "system/type/system/tree/listing")
  (data $t_0be "system/tree/listing")
  (data $t_0bf "path")
  (data $t_0c0 "count")
  (data $t_0c1 "entries")
  (data $t_0c2 "system/tree/listing-entry")
  (data $t_0c3 "next_page")
  (data $t_0c4 "system/type/system/tree/listing-entry")
  (data $t_0c5 "hash")
  (data $t_0c6 "has_children")
  (data $t_0c7 "system/type/system/tree/path")
  (data $t_0c8 "system/type/system/tree/put-request")
  (data $t_0c9 "system/tree/put-request")
  (data $t_0ca "expected_hash")
  (data $t_0cb "system/type/system/type")
  (data $t_0cc "fields")
  (data $t_0cd "system/type/field-spec")
  (data $t_0ce "layout")
  (data $t_0cf "extends")
  (data $t_0d0 "type_args")
  (data $t_0d1 "type_params")
  (data $t_0d2 "system/type/system/type/field-spec")
  (data $t_0d3 "map_of")
  (data $t_0d4 "default")
  (data $t_0d5 "array_of")
  (data $t_0d6 "optional")
  (data $t_0d7 "type_ref")
  (data $t_0d8 "union_of")
  (data $t_0d9 "byte_size")
  (data $t_0da "type_param")
  (data $t_0db "system/type/system/type/name")

  (func $disp_init (export "disp_init")
    (memory.init $c_root  (i32.const 0x460000) (i32.const 0) (i32.const 4))
    (memory.init $c_data  (i32.const 0x460010) (i32.const 0) (i32.const 4))
    (memory.init $c_type  (i32.const 0x460020) (i32.const 0) (i32.const 4))
    (memory.init $c_chash (i32.const 0x460030) (i32.const 0) (i32.const 12))
    (memory.init $c_respt (i32.const 0x460040) (i32.const 0) (i32.const 32))
    (memory.init $c_hellt (i32.const 0x460070) (i32.const 0) (i32.const 29))
    (memory.init $c_resul (i32.const 0x460090) (i32.const 0) (i32.const 6))
    (memory.init $c_stat  (i32.const 0x4600a0) (i32.const 0) (i32.const 6))
    (memory.init $c_rid   (i32.const 0x4600b0) (i32.const 0) (i32.const 10))
    (memory.init $c_op    (i32.const 0x4600c0) (i32.const 0) (i32.const 9))
    (memory.init $c_hello (i32.const 0x4600d0) (i32.const 0) (i32.const 5))
    (memory.init $c_nonce (i32.const 0x4600e0) (i32.const 0) (i32.const 5))
    (memory.init $c_pid   (i32.const 0x4600f0) (i32.const 0) (i32.const 7))
    (memory.init $c_ktyp  (i32.const 0x460100) (i32.const 0) (i32.const 9))
    (memory.init $c_prot  (i32.const 0x460110) (i32.const 0) (i32.const 9))
    (memory.init $c_ts    (i32.const 0x460120) (i32.const 0) (i32.const 9))
    (memory.init $c_hfmt  (i32.const 0x460130) (i32.const 0) (i32.const 12))
    (memory.init $c_ed    (i32.const 0x460140) (i32.const 0) (i32.const 7))
    (memory.init $c_ecp   (i32.const 0x460150) (i32.const 0) (i32.const 15))
    (memory.init $c_ecf   (i32.const 0x460160) (i32.const 0) (i32.const 12))
    ;; authenticate constants @0x461000 (slot i → 0x461000 + i*0x40)
    (memory.init $a_params  (i32.const 0x461000) (i32.const 0) (i32.const 6))
    (memory.init $a_incl    (i32.const 0x461040) (i32.const 0) (i32.const 8))
    (memory.init $a_pubk    (i32.const 0x461080) (i32.const 0) (i32.const 10))
    (memory.init $a_sigt    (i32.const 0x4610c0) (i32.const 0) (i32.const 9))
    (memory.init $a_signer  (i32.const 0x461100) (i32.const 0) (i32.const 6))
    (memory.init $a_target  (i32.const 0x461140) (i32.const 0) (i32.const 6))
    (memory.init $a_algo    (i32.const 0x461180) (i32.const 0) (i32.const 9))
    (memory.init $a_grants  (i32.const 0x4611c0) (i32.const 0) (i32.const 6))
    (memory.init $a_grantee (i32.const 0x461200) (i32.const 0) (i32.const 7))
    (memory.init $a_granter (i32.const 0x461240) (i32.const 0) (i32.const 7))
    (memory.init $a_created (i32.const 0x461280) (i32.const 0) (i32.const 10))
    (memory.init $a_token   (i32.const 0x4612c0) (i32.const 0) (i32.const 5))
    (memory.init $a_hand    (i32.const 0x461300) (i32.const 0) (i32.const 8))
    (memory.init $a_res     (i32.const 0x461340) (i32.const 0) (i32.const 9))
    (memory.init $a_ops     (i32.const 0x461380) (i32.const 0) (i32.const 10))
    (memory.init $a_include (i32.const 0x4613c0) (i32.const 0) (i32.const 7))
    (memory.init $a_code    (i32.const 0x461400) (i32.const 0) (i32.const 4))
    (memory.init $a_ktype   (i32.const 0x461440) (i32.const 0) (i32.const 8))
    (memory.init $a_tauth   (i32.const 0x461480) (i32.const 0) (i32.const 36))
    (memory.init $a_tpeer   (i32.const 0x4614c0) (i32.const 0) (i32.const 11))
    (memory.init $a_tsig    (i32.const 0x461500) (i32.const 0) (i32.const 16))
    (memory.init $a_ttok    (i32.const 0x461540) (i32.const 0) (i32.const 23))
    (memory.init $a_tgrant  (i32.const 0x461580) (i32.const 0) (i32.const 23))
    (memory.init $a_terr    (i32.const 0x4615c0) (i32.const 0) (i32.const 21))
    (memory.init $a_ed25519 (i32.const 0x461600) (i32.const 0) (i32.const 7))
    (memory.init $a_vtree   (i32.const 0x461640) (i32.const 0) (i32.const 11))
    (memory.init $a_vtype   (i32.const 0x461680) (i32.const 0) (i32.const 13))
    (memory.init $a_vhand   (i32.const 0x4616c0) (i32.const 0) (i32.const 16))
    (memory.init $a_vget    (i32.const 0x461700) (i32.const 0) (i32.const 3))
    (memory.init $a_vcap    (i32.const 0x461740) (i32.const 0) (i32.const 17))
    (memory.init $a_vreq    (i32.const 0x461780) (i32.const 0) (i32.const 7))
    (memory.init $a_einonce (i32.const 0x4617c0) (i32.const 0) (i32.const 13))
    (memory.init $a_eafail  (i32.const 0x461800) (i32.const 0) (i32.const 21))
    (memory.init $a_eimm    (i32.const 0x461840) (i32.const 0) (i32.const 17))
    (memory.init $a_ekt     (i32.const 0x461880) (i32.const 0) (i32.const 20))
    (memory.init $a_opauth  (i32.const 0x4618c0) (i32.const 0) (i32.const 12))
    (memory.init $a_ehnf    (i32.const 0x461900) (i32.const 0) (i32.const 17))
    (memory.init $a_eihf    (i32.const 0x461940) (i32.const 0) (i32.const 24))
    (memory.init $a_peers   (i32.const 0x461980) (i32.const 0) (i32.const 5))
    (memory.init $a_exclude (i32.const 0x4619c0) (i32.const 0) (i32.const 7))
    ;; tree-GET / authority / store constants @0x462000 (slot i → 0x462000 + i*0x40)
    (memory.init $b_author   (i32.const 0x462000) (i32.const 0) (i32.const 6))
    (memory.init $b_cap      (i32.const 0x462040) (i32.const 0) (i32.const 10))
    (memory.init $b_resource (i32.const 0x462080) (i32.const 0) (i32.const 8))
    (memory.init $b_targets  (i32.const 0x4620c0) (i32.const 0) (i32.const 7))
    (memory.init $b_uri      (i32.const 0x462100) (i32.const 0) (i32.const 3))
    (memory.init $b_parent   (i32.const 0x462140) (i32.const 0) (i32.const 6))
    (memory.init $b_expires  (i32.const 0x462180) (i32.const 0) (i32.const 10))
    (memory.init $b_notbef   (i32.const 0x4621c0) (i32.const 0) (i32.const 10))
    (memory.init $b_get      (i32.const 0x462200) (i32.const 0) (i32.const 3))
    (memory.init $b_capden   (i32.const 0x462240) (i32.const 0) (i32.const 17))
    (memory.init $b_chaind   (i32.const 0x462280) (i32.const 0) (i32.const 20))
    (memory.init $b_invpath  (i32.const 0x4622c0) (i32.const 0) (i32.const 12))
    (memory.init $b_notfound (i32.const 0x462300) (i32.const 0) (i32.const 9))
    (memory.init $b_unresg   (i32.const 0x462340) (i32.const 0) (i32.const 20))
    (memory.init $b_paytoobig (i32.const 0x462420) (i32.const 0) (i32.const 17))
    (memory.init $b_entity  (i32.const 0x466700) (i32.const 0) (i32.const 6))
    (memory.init $b_exphash (i32.const 0x466720) (i32.const 0) (i32.const 13))
    (memory.init $b_hashmm  (i32.const 0x466740) (i32.const 0) (i32.const 13))
    ;; §6.13a / §10.1 handler register/unregister constants
    (memory.init $b_thand      (i32.const 0x466800) (i32.const 0) (i32.const 14))
    (memory.init $b_tregres    (i32.const 0x466820) (i32.const 0) (i32.const 30))
    (memory.init $b_grantsp    (i32.const 0x466860) (i32.const 0) (i32.const 25))
    (memory.init $b_sigpp      (i32.const 0x466890) (i32.const 0) (i32.const 17))
    (memory.init $b_kiface     (i32.const 0x4668b0) (i32.const 0) (i32.const 9))
    (memory.init $b_kmanif     (i32.const 0x4668c0) (i32.const 0) (i32.const 8))
    (memory.init $b_kexpr      (i32.const 0x4668d0) (i32.const 0) (i32.const 15))
    (memory.init $b_kintsc     (i32.const 0x4668f0) (i32.const 0) (i32.const 14))
    (memory.init $b_kreqsc     (i32.const 0x466910) (i32.const 0) (i32.const 15))
    (memory.init $b_kgrant     (i32.const 0x466930) (i32.const 0) (i32.const 5))
    (memory.init $b_register   (i32.const 0x466940) (i32.const 0) (i32.const 8))
    (memory.init $b_unregister (i32.const 0x466960) (i32.const 0) (i32.const 10))
    (memory.init $b_ambigres   (i32.const 0x466980) (i32.const 0) (i32.const 18))
    (memory.init $b_manifmm    (i32.const 0x4669b0) (i32.const 0) (i32.const 25))
    (memory.init $b_pwild      (i32.const 0x4669e0) (i32.const 0) (i32.const 4))
    ;; §7a conformance-handler constants @0x466a00 (slot → 0x466a00 + i*0x20/0x40)
    (memory.init $v_pecho    (i32.const 0x466a00) (i32.const 0) (i32.const 20))
    (memory.init $v_pdisp    (i32.const 0x466a40) (i32.const 0) (i32.const 33))
    (memory.init $v_hiecho   (i32.const 0x466a80) (i32.const 0) (i32.const 35))
    (memory.init $v_hidisp   (i32.const 0x466ac0) (i32.const 0) (i32.const 48))
    (memory.init $v_dispatch (i32.const 0x466b00) (i32.const 0) (i32.const 8))
    (memory.init $v_echo     (i32.const 0x466b20) (i32.const 0) (i32.const 4))
    (memory.init $v_value    (i32.const 0x466b40) (i32.const 0) (i32.const 5))
    (memory.init $v_target   (i32.const 0x466b60) (i32.const 0) (i32.const 6))
    (memory.init $v_rcap     (i32.const 0x466b80) (i32.const 0) (i32.const 18))
    (memory.init $v_rgrant   (i32.const 0x466bc0) (i32.const 0) (i32.const 15))
    (memory.init $v_rcsig    (i32.const 0x466c00) (i32.const 0) (i32.const 21))
    (memory.init $v_ridpfx   (i32.const 0x466c40) (i32.const 0) (i32.const 4))
    (memory.init $b_forbidpat (i32.const 0x466c60) (i32.const 0) (i32.const 17))
    (memory.init $b_sysexact  (i32.const 0x466c80) (i32.const 0) (i32.const 6))
    (memory.init $b_sysslash  (i32.const 0x466ca0) (i32.const 0) (i32.const 7))
    (memory.init $b_scheme   (i32.const 0x462380) (i32.const 0) (i32.const 9))
    (memory.init $b_star     (i32.const 0x4623c0) (i32.const 0) (i32.const 1))
    (memory.init $b_slashstar (i32.const 0x462400) (i32.const 0) (i32.const 2))
    (memory.init $b_pconn    (i32.const 0x462440) (i32.const 0) (i32.const 38))
    (memory.init $b_ptree    (i32.const 0x462480) (i32.const 0) (i32.const 26))
    (memory.init $b_pcapa    (i32.const 0x4624c0) (i32.const 0) (i32.const 32))
    (memory.init $b_plist    (i32.const 0x462500) (i32.const 0) (i32.const 15))
    (memory.init $b_name     (i32.const 0x462540) (i32.const 0) (i32.const 4))
    (memory.init $b_pattern  (i32.const 0x462580) (i32.const 0) (i32.const 7))
    (memory.init $b_intype   (i32.const 0x4625c0) (i32.const 0) (i32.const 10))
    (memory.init $b_outtype  (i32.const 0x462600) (i32.const 0) (i32.const 11))
    (memory.init $b_tiface   (i32.const 0x462640) (i32.const 0) (i32.const 24))
    (memory.init $b_vconn    (i32.const 0x462680) (i32.const 0) (i32.const 7))
    (memory.init $b_vtree    (i32.const 0x4626c0) (i32.const 0) (i32.const 4))
    (memory.init $b_vcapa    (i32.const 0x462700) (i32.const 0) (i32.const 10))
    (memory.init $b_scpconn  (i32.const 0x462740) (i32.const 0) (i32.const 23))
    (memory.init $b_put      (i32.const 0x462780) (i32.const 0) (i32.const 3))
    (memory.init $b_deleg    (i32.const 0x4627c0) (i32.const 0) (i32.const 8))
    (memory.init $b_revoke   (i32.const 0x462800) (i32.const 0) (i32.const 6))
    (memory.init $b_primany  (i32.const 0x462840) (i32.const 0) (i32.const 13))
    (memory.init $b_tlist    (i32.const 0x462880) (i32.const 0) (i32.const 19))
    (memory.init $b_tlent    (i32.const 0x4628c0) (i32.const 0) (i32.const 25))
    (memory.init $b_entries  (i32.const 0x462900) (i32.const 0) (i32.const 7))
    (memory.init $b_path     (i32.const 0x462940) (i32.const 0) (i32.const 4))
    (memory.init $b_diff     (i32.const 0x462980) (i32.const 0) (i32.const 4))
    (memory.init $b_merge    (i32.const 0x4629c0) (i32.const 0) (i32.const 5))
    (memory.init $b_extract  (i32.const 0x462a00) (i32.const 0) (i32.const 7))
    (memory.init $b_snapshot (i32.const 0x462a40) (i32.const 0) (i32.const 8))
    (memory.init $b_unsupop  (i32.const 0x462a80) (i32.const 0) (i32.const 21))
    (memory.init $b_ppolicy   (i32.const 0x462ac0) (i32.const 0) (i32.const 25))
    (memory.init $b_prevoc    (i32.const 0x462b00) (i32.const 0) (i32.const 30))
    (memory.init $b_configure (i32.const 0x462b40) (i32.const 0) (i32.const 9))
    (memory.init $b_invparams (i32.const 0x462b80) (i32.const 0) (i32.const 14))
    (memory.init $b_hexchars  (i32.const 0x462bc0) (i32.const 0) (i32.const 16))
    ;; ===== §9.5 Core Type Floor string constants =====
    (memory.init $t_000 (i32.const 0x463000) (i32.const 0) (i32.const 11))
    (memory.init $t_001 (i32.const 0x463040) (i32.const 0) (i32.const 23))
    (memory.init $t_002 (i32.const 0x463080) (i32.const 0) (i32.const 11))
    (memory.init $t_003 (i32.const 0x4630c0) (i32.const 0) (i32.const 4))
    (memory.init $t_004 (i32.const 0x463100) (i32.const 0) (i32.const 13))
    (memory.init $t_005 (i32.const 0x463140) (i32.const 0) (i32.const 4))
    (memory.init $t_006 (i32.const 0x463180) (i32.const 0) (i32.const 16))
    (memory.init $t_007 (i32.const 0x4631c0) (i32.const 0) (i32.const 12))
    (memory.init $t_008 (i32.const 0x463200) (i32.const 0) (i32.const 11))
    (memory.init $t_009 (i32.const 0x463240) (i32.const 0) (i32.const 25))
    (memory.init $t_00a (i32.const 0x463280) (i32.const 0) (i32.const 13))
    (memory.init $t_00b (i32.const 0x4632c0) (i32.const 0) (i32.const 4))
    (memory.init $t_00c (i32.const 0x463300) (i32.const 0) (i32.const 8))
    (memory.init $t_00d (i32.const 0x463340) (i32.const 0) (i32.const 18))
    (memory.init $t_00e (i32.const 0x463380) (i32.const 0) (i32.const 6))
    (memory.init $t_00f (i32.const 0x4633c0) (i32.const 0) (i32.const 25))
    (memory.init $t_010 (i32.const 0x463400) (i32.const 0) (i32.const 26))
    (memory.init $t_011 (i32.const 0x463440) (i32.const 0) (i32.const 14))
    (memory.init $t_012 (i32.const 0x463480) (i32.const 0) (i32.const 27))
    (memory.init $t_013 (i32.const 0x4634c0) (i32.const 0) (i32.const 15))
    (memory.init $t_014 (i32.const 0x463500) (i32.const 0) (i32.const 27))
    (memory.init $t_015 (i32.const 0x463540) (i32.const 0) (i32.const 15))
    (memory.init $t_016 (i32.const 0x463580) (i32.const 0) (i32.const 25))
    (memory.init $t_017 (i32.const 0x4635c0) (i32.const 0) (i32.const 13))
    (memory.init $t_018 (i32.const 0x463600) (i32.const 0) (i32.const 26))
    (memory.init $t_019 (i32.const 0x463640) (i32.const 0) (i32.const 14))
    (memory.init $t_01a (i32.const 0x463680) (i32.const 0) (i32.const 28))
    (memory.init $t_01b (i32.const 0x4636c0) (i32.const 0) (i32.const 26))
    (memory.init $t_01c (i32.const 0x463700) (i32.const 0) (i32.const 14))
    (memory.init $t_01d (i32.const 0x463740) (i32.const 0) (i32.const 25))
    (memory.init $t_01e (i32.const 0x463780) (i32.const 0) (i32.const 13))
    (memory.init $t_01f (i32.const 0x4637c0) (i32.const 0) (i32.const 3))
    (memory.init $t_020 (i32.const 0x463800) (i32.const 0) (i32.const 6))
    (memory.init $t_021 (i32.const 0x463840) (i32.const 0) (i32.const 7))
    (memory.init $t_022 (i32.const 0x463880) (i32.const 0) (i32.const 16))
    (memory.init $t_023 (i32.const 0x4638c0) (i32.const 0) (i32.const 8))
    (memory.init $t_024 (i32.const 0x463900) (i32.const 0) (i32.const 13))
    (memory.init $t_025 (i32.const 0x463940) (i32.const 0) (i32.const 15))
    (memory.init $t_026 (i32.const 0x463980) (i32.const 0) (i32.const 46))
    (memory.init $t_027 (i32.const 0x4639c0) (i32.const 0) (i32.const 34))
    (memory.init $t_028 (i32.const 0x463a00) (i32.const 0) (i32.const 6))
    (memory.init $t_029 (i32.const 0x463a40) (i32.const 0) (i32.const 29))
    (memory.init $t_02a (i32.const 0x463a80) (i32.const 0) (i32.const 6))
    (memory.init $t_02b (i32.const 0x463ac0) (i32.const 0) (i32.const 6))
    (memory.init $t_02c (i32.const 0x463b00) (i32.const 0) (i32.const 48))
    (memory.init $t_02d (i32.const 0x463b40) (i32.const 0) (i32.const 36))
    (memory.init $t_02e (i32.const 0x463b80) (i32.const 0) (i32.const 13))
    (memory.init $t_02f (i32.const 0x463bc0) (i32.const 0) (i32.const 18))
    (memory.init $t_030 (i32.const 0x463c00) (i32.const 0) (i32.const 20))
    (memory.init $t_031 (i32.const 0x463c40) (i32.const 0) (i32.const 35))
    (memory.init $t_032 (i32.const 0x463c80) (i32.const 0) (i32.const 23))
    (memory.init $t_033 (i32.const 0x463cc0) (i32.const 0) (i32.const 5))
    (memory.init $t_034 (i32.const 0x463d00) (i32.const 0) (i32.const 41))
    (memory.init $t_035 (i32.const 0x463d40) (i32.const 0) (i32.const 5))
    (memory.init $t_036 (i32.const 0x463d80) (i32.const 0) (i32.const 26))
    (memory.init $t_037 (i32.const 0x463dc0) (i32.const 0) (i32.const 8))
    (memory.init $t_038 (i32.const 0x463e00) (i32.const 0) (i32.const 28))
    (memory.init $t_039 (i32.const 0x463e40) (i32.const 0) (i32.const 9))
    (memory.init $t_03a (i32.const 0x463e80) (i32.const 0) (i32.const 10))
    (memory.init $t_03b (i32.const 0x463ec0) (i32.const 0) (i32.const 10))
    (memory.init $t_03c (i32.const 0x463f00) (i32.const 0) (i32.const 11))
    (memory.init $t_03d (i32.const 0x463f40) (i32.const 0) (i32.const 38))
    (memory.init $t_03e (i32.const 0x463f80) (i32.const 0) (i32.const 7))
    (memory.init $t_03f (i32.const 0x463fc0) (i32.const 0) (i32.const 7))
    (memory.init $t_040 (i32.const 0x464000) (i32.const 0) (i32.const 43))
    (memory.init $t_041 (i32.const 0x464040) (i32.const 0) (i32.const 31))
    (memory.init $t_042 (i32.const 0x464080) (i32.const 0) (i32.const 7))
    (memory.init $t_043 (i32.const 0x4640c0) (i32.const 0) (i32.const 9))
    (memory.init $t_044 (i32.const 0x464100) (i32.const 0) (i32.const 40))
    (memory.init $t_045 (i32.const 0x464140) (i32.const 0) (i32.const 42))
    (memory.init $t_046 (i32.const 0x464180) (i32.const 0) (i32.const 30))
    (memory.init $t_047 (i32.const 0x4641c0) (i32.const 0) (i32.const 5))
    (memory.init $t_048 (i32.const 0x464200) (i32.const 0) (i32.const 12))
    (memory.init $t_049 (i32.const 0x464240) (i32.const 0) (i32.const 37))
    (memory.init $t_04a (i32.const 0x464280) (i32.const 0) (i32.const 25))
    (memory.init $t_04b (i32.const 0x4642c0) (i32.const 0) (i32.const 40))
    (memory.init $t_04c (i32.const 0x464300) (i32.const 0) (i32.const 28))
    (memory.init $t_04d (i32.const 0x464340) (i32.const 0) (i32.const 6))
    (memory.init $t_04e (i32.const 0x464380) (i32.const 0) (i32.const 10))
    (memory.init $t_04f (i32.const 0x4643c0) (i32.const 0) (i32.const 44))
    (memory.init $t_050 (i32.const 0x464400) (i32.const 0) (i32.const 32))
    (memory.init $t_051 (i32.const 0x464440) (i32.const 0) (i32.const 35))
    (memory.init $t_052 (i32.const 0x464480) (i32.const 0) (i32.const 23))
    (memory.init $t_053 (i32.const 0x4644c0) (i32.const 0) (i32.const 7))
    (memory.init $t_054 (i32.const 0x464500) (i32.const 0) (i32.const 7))
    (memory.init $t_055 (i32.const 0x464540) (i32.const 0) (i32.const 10))
    (memory.init $t_056 (i32.const 0x464580) (i32.const 0) (i32.const 10))
    (memory.init $t_057 (i32.const 0x4645c0) (i32.const 0) (i32.const 10))
    (memory.init $t_058 (i32.const 0x464600) (i32.const 0) (i32.const 15))
    (memory.init $t_059 (i32.const 0x464640) (i32.const 0) (i32.const 22))
    (memory.init $t_05a (i32.const 0x464680) (i32.const 0) (i32.const 18))
    (memory.init $t_05b (i32.const 0x4646c0) (i32.const 0) (i32.const 34))
    (memory.init $t_05c (i32.const 0x464700) (i32.const 0) (i32.const 22))
    (memory.init $t_05d (i32.const 0x464740) (i32.const 0) (i32.const 32))
    (memory.init $t_05e (i32.const 0x464780) (i32.const 0) (i32.const 20))
    (memory.init $t_05f (i32.const 0x4647c0) (i32.const 0) (i32.const 3))
    (memory.init $t_060 (i32.const 0x464800) (i32.const 0) (i32.const 9))
    (memory.init $t_061 (i32.const 0x464840) (i32.const 0) (i32.const 27))
    (memory.init $t_062 (i32.const 0x464880) (i32.const 0) (i32.const 15))
    (memory.init $t_063 (i32.const 0x4648c0) (i32.const 0) (i32.const 26))
    (memory.init $t_064 (i32.const 0x464900) (i32.const 0) (i32.const 14))
    (memory.init $t_065 (i32.const 0x464940) (i32.const 0) (i32.const 9))
    (memory.init $t_066 (i32.const 0x464980) (i32.const 0) (i32.const 9))
    (memory.init $t_067 (i32.const 0x4649c0) (i32.const 0) (i32.const 14))
    (memory.init $t_068 (i32.const 0x464a00) (i32.const 0) (i32.const 15))
    (memory.init $t_069 (i32.const 0x464a40) (i32.const 0) (i32.const 36))
    (memory.init $t_06a (i32.const 0x464a80) (i32.const 0) (i32.const 24))
    (memory.init $t_06b (i32.const 0x464ac0) (i32.const 0) (i32.const 4))
    (memory.init $t_06c (i32.const 0x464b00) (i32.const 0) (i32.const 7))
    (memory.init $t_06d (i32.const 0x464b40) (i32.const 0) (i32.const 29))
    (memory.init $t_06e (i32.const 0x464b80) (i32.const 0) (i32.const 35))
    (memory.init $t_06f (i32.const 0x464bc0) (i32.const 0) (i32.const 23))
    (memory.init $t_070 (i32.const 0x464c00) (i32.const 0) (i32.const 41))
    (memory.init $t_071 (i32.const 0x464c40) (i32.const 0) (i32.const 10))
    (memory.init $t_072 (i32.const 0x464c80) (i32.const 0) (i32.const 16))
    (memory.init $t_073 (i32.const 0x464cc0) (i32.const 0) (i32.const 11))
    (memory.init $t_074 (i32.const 0x464d00) (i32.const 0) (i32.const 43))
    (memory.init $t_075 (i32.const 0x464d40) (i32.const 0) (i32.const 31))
    (memory.init $t_076 (i32.const 0x464d80) (i32.const 0) (i32.const 5))
    (memory.init $t_077 (i32.const 0x464dc0) (i32.const 0) (i32.const 8))
    (memory.init $t_078 (i32.const 0x464e00) (i32.const 0) (i32.const 15))
    (memory.init $t_079 (i32.const 0x464e40) (i32.const 0) (i32.const 42))
    (memory.init $t_07a (i32.const 0x464e80) (i32.const 0) (i32.const 30))
    (memory.init $t_07b (i32.const 0x464ec0) (i32.const 0) (i32.const 5))
    (memory.init $t_07c (i32.const 0x464f00) (i32.const 0) (i32.const 23))
    (memory.init $t_07d (i32.const 0x464f40) (i32.const 0) (i32.const 11))
    (memory.init $t_07e (i32.const 0x464f80) (i32.const 0) (i32.const 6))
    (memory.init $t_07f (i32.const 0x464fc0) (i32.const 0) (i32.const 23))
    (memory.init $t_080 (i32.const 0x465000) (i32.const 0) (i32.const 11))
    (memory.init $t_081 (i32.const 0x465040) (i32.const 0) (i32.const 7))
    (memory.init $t_082 (i32.const 0x465080) (i32.const 0) (i32.const 14))
    (memory.init $t_083 (i32.const 0x4650c0) (i32.const 0) (i32.const 8))
    (memory.init $t_084 (i32.const 0x465100) (i32.const 0) (i32.const 10))
    (memory.init $t_085 (i32.const 0x465140) (i32.const 0) (i32.const 26))
    (memory.init $t_086 (i32.const 0x465180) (i32.const 0) (i32.const 48))
    (memory.init $t_087 (i32.const 0x4651c0) (i32.const 0) (i32.const 36))
    (memory.init $t_088 (i32.const 0x465200) (i32.const 0) (i32.const 5))
    (memory.init $t_089 (i32.const 0x465240) (i32.const 0) (i32.const 41))
    (memory.init $t_08a (i32.const 0x465280) (i32.const 0) (i32.const 29))
    (memory.init $t_08b (i32.const 0x4652c0) (i32.const 0) (i32.const 9))
    (memory.init $t_08c (i32.const 0x465300) (i32.const 0) (i32.const 9))
    (memory.init $t_08d (i32.const 0x465340) (i32.const 0) (i32.const 9))
    (memory.init $t_08e (i32.const 0x465380) (i32.const 0) (i32.const 10))
    (memory.init $t_08f (i32.const 0x4653c0) (i32.const 0) (i32.const 11))
    (memory.init $t_090 (i32.const 0x465400) (i32.const 0) (i32.const 12))
    (memory.init $t_091 (i32.const 0x465440) (i32.const 0) (i32.const 36))
    (memory.init $t_092 (i32.const 0x465480) (i32.const 0) (i32.const 24))
    (memory.init $t_093 (i32.const 0x4654c0) (i32.const 0) (i32.const 33))
    (memory.init $t_094 (i32.const 0x465500) (i32.const 0) (i32.const 21))
    (memory.init $t_095 (i32.const 0x465540) (i32.const 0) (i32.const 4))
    (memory.init $t_096 (i32.const 0x465580) (i32.const 0) (i32.const 7))
    (memory.init $t_097 (i32.const 0x4655c0) (i32.const 0) (i32.const 15))
    (memory.init $t_098 (i32.const 0x465600) (i32.const 0) (i32.const 35))
    (memory.init $t_099 (i32.const 0x465640) (i32.const 0) (i32.const 23))
    (memory.init $t_09a (i32.const 0x465680) (i32.const 0) (i32.const 6))
    (memory.init $t_09b (i32.const 0x4656c0) (i32.const 0) (i32.const 6))
    (memory.init $t_09c (i32.const 0x465700) (i32.const 0) (i32.const 6))
    (memory.init $t_09d (i32.const 0x465740) (i32.const 0) (i32.const 8))
    (memory.init $t_09e (i32.const 0x465780) (i32.const 0) (i32.const 31))
    (memory.init $t_09f (i32.const 0x4657c0) (i32.const 0) (i32.const 10))
    (memory.init $t_0a0 (i32.const 0x465800) (i32.const 0) (i32.const 10))
    (memory.init $t_0a1 (i32.const 0x465840) (i32.const 0) (i32.const 10))
    (memory.init $t_0a2 (i32.const 0x465880) (i32.const 0) (i32.const 13))
    (memory.init $t_0a3 (i32.const 0x4658c0) (i32.const 0) (i32.const 18))
    (memory.init $t_0a4 (i32.const 0x465900) (i32.const 0) (i32.const 25))
    (memory.init $t_0a5 (i32.const 0x465940) (i32.const 0) (i32.const 44))
    (memory.init $t_0a6 (i32.const 0x465980) (i32.const 0) (i32.const 32))
    (memory.init $t_0a7 (i32.const 0x4659c0) (i32.const 0) (i32.const 6))
    (memory.init $t_0a8 (i32.const 0x465a00) (i32.const 0) (i32.const 6))
    (memory.init $t_0a9 (i32.const 0x465a40) (i32.const 0) (i32.const 10))
    (memory.init $t_0aa (i32.const 0x465a80) (i32.const 0) (i32.const 24))
    (memory.init $t_0ab (i32.const 0x465ac0) (i32.const 0) (i32.const 43))
    (memory.init $t_0ac (i32.const 0x465b00) (i32.const 0) (i32.const 7))
    (memory.init $t_0ad (i32.const 0x465b40) (i32.const 0) (i32.const 34))
    (memory.init $t_0ae (i32.const 0x465b80) (i32.const 0) (i32.const 7))
    (memory.init $t_0af (i32.const 0x465bc0) (i32.const 0) (i32.const 10))
    (memory.init $t_0b0 (i32.const 0x465c00) (i32.const 0) (i32.const 18))
    (memory.init $t_0b1 (i32.const 0x465c40) (i32.const 0) (i32.const 28))
    (memory.init $t_0b2 (i32.const 0x465c80) (i32.const 0) (i32.const 16))
    (memory.init $t_0b3 (i32.const 0x465cc0) (i32.const 0) (i32.const 6))
    (memory.init $t_0b4 (i32.const 0x465d00) (i32.const 0) (i32.const 6))
    (memory.init $t_0b5 (i32.const 0x465d40) (i32.const 0) (i32.const 9))
    (memory.init $t_0b6 (i32.const 0x465d80) (i32.const 0) (i32.const 9))
    (memory.init $t_0b7 (i32.const 0x465dc0) (i32.const 0) (i32.const 35))
    (memory.init $t_0b8 (i32.const 0x465e00) (i32.const 0) (i32.const 23))
    (memory.init $t_0b9 (i32.const 0x465e40) (i32.const 0) (i32.const 4))
    (memory.init $t_0ba (i32.const 0x465e80) (i32.const 0) (i32.const 5))
    (memory.init $t_0bb (i32.const 0x465ec0) (i32.const 0) (i32.const 6))
    (memory.init $t_0bc (i32.const 0x465f00) (i32.const 0) (i32.const 7))
    (memory.init $t_0bd (i32.const 0x465f40) (i32.const 0) (i32.const 31))
    (memory.init $t_0be (i32.const 0x465f80) (i32.const 0) (i32.const 19))
    (memory.init $t_0bf (i32.const 0x465fc0) (i32.const 0) (i32.const 4))
    (memory.init $t_0c0 (i32.const 0x466000) (i32.const 0) (i32.const 5))
    (memory.init $t_0c1 (i32.const 0x466040) (i32.const 0) (i32.const 7))
    (memory.init $t_0c2 (i32.const 0x466080) (i32.const 0) (i32.const 25))
    (memory.init $t_0c3 (i32.const 0x4660c0) (i32.const 0) (i32.const 9))
    (memory.init $t_0c4 (i32.const 0x466100) (i32.const 0) (i32.const 37))
    (memory.init $t_0c5 (i32.const 0x466140) (i32.const 0) (i32.const 4))
    (memory.init $t_0c6 (i32.const 0x466180) (i32.const 0) (i32.const 12))
    (memory.init $t_0c7 (i32.const 0x4661c0) (i32.const 0) (i32.const 28))
    (memory.init $t_0c8 (i32.const 0x466200) (i32.const 0) (i32.const 35))
    (memory.init $t_0c9 (i32.const 0x466240) (i32.const 0) (i32.const 23))
    (memory.init $t_0ca (i32.const 0x466280) (i32.const 0) (i32.const 13))
    (memory.init $t_0cb (i32.const 0x4662c0) (i32.const 0) (i32.const 23))
    (memory.init $t_0cc (i32.const 0x466300) (i32.const 0) (i32.const 6))
    (memory.init $t_0cd (i32.const 0x466340) (i32.const 0) (i32.const 22))
    (memory.init $t_0ce (i32.const 0x466380) (i32.const 0) (i32.const 6))
    (memory.init $t_0cf (i32.const 0x4663c0) (i32.const 0) (i32.const 7))
    (memory.init $t_0d0 (i32.const 0x466400) (i32.const 0) (i32.const 9))
    (memory.init $t_0d1 (i32.const 0x466440) (i32.const 0) (i32.const 11))
    (memory.init $t_0d2 (i32.const 0x466480) (i32.const 0) (i32.const 34))
    (memory.init $t_0d3 (i32.const 0x4664c0) (i32.const 0) (i32.const 6))
    (memory.init $t_0d4 (i32.const 0x466500) (i32.const 0) (i32.const 7))
    (memory.init $t_0d5 (i32.const 0x466540) (i32.const 0) (i32.const 8))
    (memory.init $t_0d6 (i32.const 0x466580) (i32.const 0) (i32.const 8))
    (memory.init $t_0d7 (i32.const 0x4665c0) (i32.const 0) (i32.const 8))
    (memory.init $t_0d8 (i32.const 0x466600) (i32.const 0) (i32.const 8))
    (memory.init $t_0d9 (i32.const 0x466640) (i32.const 0) (i32.const 9))
    (memory.init $t_0da (i32.const 0x466680) (i32.const 0) (i32.const 10))
    (memory.init $t_0db (i32.const 0x4666c0) (i32.const 0) (i32.const 28))
    (call $store_init))

  ;; array_contains(arrp, needle, nlen) → 1 if the CBOR text/bstr array at $arrp contains a
  ;; byte-equal element, else 0. Non-string elements are skipped (never match).
  (func $array_contains (param $arrp i32) (param $needle i32) (param $nlen i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $estart i32) (local $ep i32) (local $elen i32) (local $emaj i32)
    (local.set $p (call $rd_head (local.get $arrp)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))     ;; not an array
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $estart (local.get $p))
      (local.set $ep (call $rd_head (local.get $p)))
      (local.set $emaj (global.get $g_major))
      (local.set $elen (i32.wrap_i64 (global.get $g_arg)))
      (if (i32.or (i32.eq (local.get $emaj) (i32.const 2)) (i32.eq (local.get $emaj) (i32.const 3)))
        (then (if (call $streq (local.get $ep) (local.get $elen) (local.get $needle) (local.get $nlen))
          (then (return (i32.const 1))))))
      (local.set $p (call $skip (local.get $estart)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  ;; §4.5 hello negotiation: if params.data advertises hash_formats without "ecfv1-sha256",
  ;; reject 400 incompatible_hash_format; if it advertises key_types without "ed25519", reject
  ;; 400 unsupported_key_type. Absent fields ⇒ no reject (the happy path advertises our sets).
  ;; Returns the built error length (>0) if rejected, else 0 (proceed to build_hello).
  (func $hello_neg (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $params i32) (local $pdata i32) (local $hf i32) (local $kt i32) (local $pid i32) (local $pidp i32)
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))    ;; "params"
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))   ;; "data"
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $hf (call $map_find (local.get $pdata) (i32.const 0x460130) (i32.const 12)))       ;; "hash_formats"
    (if (i32.ne (local.get $hf) (i32.const -1))
      (then (if (i32.eqz (call $array_contains (local.get $hf) (i32.const 0x460160) (i32.const 12)))  ;; ecfv1-sha256
        (then (return (call $build_error (local.get $out) (i32.const 0x461940) (i32.const 24) (i32.const 400) (local.get $rid) (local.get $rlen)))))))
    (local.set $kt (call $map_find (local.get $pdata) (i32.const 0x460100) (i32.const 9)))         ;; "key_types"
    (if (i32.ne (local.get $kt) (i32.const -1))
      (then (if (i32.eqz (call $array_contains (local.get $kt) (i32.const 0x461600) (i32.const 7)))  ;; ed25519
        (then (return (call $build_error (local.get $out) (i32.const 0x461880) (i32.const 20) (i32.const 400) (local.get $rid) (local.get $rlen)))))))
    ;; §7.1 agility: classify the hello peer_id's key_type multihash prefix; anything but
    ;; ed25519 (kt=1) — or an unparseable id — is unverifiable here → 400 unsupported_key_type.
    (local.set $pid (call $map_find (local.get $pdata) (i32.const 0x4600f0) (i32.const 7)))          ;; "peer_id"
    (if (i32.ne (local.get $pid) (i32.const -1))
      (then
        (local.set $pidp (call $rd_head (local.get $pid)))
        (if (i32.or (call $peerid_parse (local.get $pidp) (i32.wrap_i64 (global.get $g_arg)) (i32.const 0x972200) (i32.const 0x972208) (i32.const 0x972210) (i32.const 0x972260))
                    (i64.ne (i64.load (i32.const 0x972200)) (i64.const 1)))
          (then (return (call $build_error (local.get $out) (i32.const 0x461880) (i32.const 20) (i32.const 400) (local.get $rid) (local.get $rlen)))))))
    (i32.const 0))

  ;; build the hello RESPONSE at $out; echo request_id [rid,rlen]. Returns out length.
  ;; $sess = per-connection session state {nonce(32)@0, hello_done(4)@32, auth_done(4)@36}: the nonce we issue
  ;; here is STORED so authenticate can enforce the §4.6 nonce-echo check.
  (func $build_hello (param $out i32) (param $rid i32) (param $rlen i32) (param $sess i32) (result i32)
    (local $rdlen i32) (local $relen i32) (local $rdatalen i32) (local $ms i64)

    (drop (call $random_get (local.get $sess) (i32.const 32)))             ;; issued nonce → session
    (i32.store (i32.add (local.get $sess) (i32.const 32)) (i32.const 1))    ;; hello_done = 1
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))

    ;; result-data a6 @0x900000: {nonce,peer_id,key_types,protocols,timestamp,hash_formats}
    (global.set $g_wp (i32.const 0x900000))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x4600e0) (i32.const 5))  (call $w_bstr (local.get $sess) (i32.const 32))
    (call $w_text (i32.const 0x4600f0) (i32.const 7))  (call $w_text (i32.const 0x420200) (i32.load (i32.const 0x4202F0)))
    (call $w_text (i32.const 0x460100) (i32.const 9))  (call $w_array (i64.const 1)) (call $w_text (i32.const 0x460140) (i32.const 7))
    (call $w_text (i32.const 0x460110) (i32.const 9))  (call $w_array (i64.const 1)) (call $w_text (i32.const 0x460150) (i32.const 15))
    (call $w_text (i32.const 0x460120) (i32.const 9))  (call $w_uint (local.get $ms))
    (call $w_text (i32.const 0x460130) (i32.const 12)) (call $w_array (i64.const 1)) (call $w_text (i32.const 0x460160) (i32.const 12))
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x900000)))
    (drop (call $content_hash (i32.const 0x460070) (i32.const 29) (i32.const 0x900000) (local.get $rdlen) (i32.const 0x920000)))

    ;; result entity @0x908000: {data:<a6>, type:"…/connect/hello", content_hash:<33>}
    (global.set $g_wp (i32.const 0x908000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460010) (i32.const 4))  (call $w_bytes (i32.const 0x900000) (local.get $rdlen))
    (call $w_text (i32.const 0x460020) (i32.const 4))  (call $w_text (i32.const 0x460070) (i32.const 29))
    (call $w_text (i32.const 0x460030) (i32.const 12)) (call $w_bstr (i32.const 0x920000) (i32.const 33))
    (local.set $relen (i32.sub (global.get $g_wp) (i32.const 0x908000)))

    ;; response-data a3 @0x910000: {result:<entity>, status:200, request_id:<echo>}
    (global.set $g_wp (i32.const 0x910000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))  (call $w_bytes (i32.const 0x908000) (local.get $relen))
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (i64.const 200))
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (local.get $rid) (local.get $rlen))
    (local.set $rdatalen (i32.sub (global.get $g_wp) (i32.const 0x910000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x910000) (local.get $rdatalen) (i32.const 0x920040)))

    ;; envelope @$out: { root: {data:<a3>, type:"…/execute/response", content_hash:<33>} }
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x460000) (i32.const 4))          ;; "root"
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460010) (i32.const 4))  (call $w_bytes (i32.const 0x910000) (local.get $rdatalen))
    (call $w_text (i32.const 0x460020) (i32.const 4))  (call $w_text (i32.const 0x460040) (i32.const 32))
    (call $w_text (i32.const 0x460030) (i32.const 12)) (call $w_bstr (i32.const 0x920040) (i32.const 33))
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; --- authenticate helpers (§4.6) -------------------------------------------

  ;; emit an entity map {data:<raw dp,dl>, type:<text tp,tl>, content_hash:<33 @ch>} at g_wp.
  (func $w_entity (param $tp i32) (param $tl i32) (param $dp i32) (param $dl i32) (param $ch i32)
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460010) (i32.const 4))  (call $w_bytes (local.get $dp) (local.get $dl))  ;; "data"
    (call $w_text (i32.const 0x460020) (i32.const 4))  (call $w_text  (local.get $tp) (local.get $tl))  ;; "type"
    (call $w_text (i32.const 0x460030) (i32.const 12)) (call $w_bstr  (local.get $ch) (i32.const 33)))  ;; "content_hash"

  ;; signed byte compare of 33 bytes: a[i]-b[i] at first difference, 0 if equal.
  (func $mcmp33 (param $a i32) (param $b i32) (result i32)
    (local $i i32) (local $x i32) (local $y i32)
    (block $done (loop $L
      (br_if $done (i32.eq (local.get $i) (i32.const 33)))
      (local.set $x (i32.load8_u (i32.add (local.get $a) (local.get $i))))
      (local.set $y (i32.load8_u (i32.add (local.get $b) (local.get $i))))
      (if (i32.ne (local.get $x) (local.get $y))
        (then (return (i32.sub (local.get $x) (local.get $y)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 0))

  ;; build a system/protocol/error EXECUTE_RESPONSE {result:{code}, status, request_id} at
  ;; $out (map(1) root, no `included`); return its byte length. Scratch: 0x970000/0x971000,
  ;; hashes 0x920300/0x920340.
  (func $build_error (param $out i32) (param $code i32) (param $clen i32) (param $status i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $edlen i32) (local $rdlen i32)
    (global.set $g_wp (i32.const 0x970000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x461400) (i32.const 4))   (call $w_text (local.get $code) (local.get $clen))  ;; {code:<text>}
    (local.set $edlen (i32.sub (global.get $g_wp) (i32.const 0x970000)))
    (drop (call $content_hash (i32.const 0x4615c0) (i32.const 21) (i32.const 0x970000) (local.get $edlen) (i32.const 0x920300)))
    (global.set $g_wp (i32.const 0x971000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))   ;; "result"
    (call $w_entity (i32.const 0x4615c0) (i32.const 21) (i32.const 0x970000) (local.get $edlen) (i32.const 0x920300))
    (call $w_text (i32.const 0x4600a0) (i32.const 6))   (call $w_uint (i64.extend_i32_u (local.get $status)))  ;; "status"
    (call $w_text (i32.const 0x4600b0) (i32.const 10))  (call $w_text (local.get $rid) (local.get $rlen))       ;; "request_id"
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x971000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x971000) (local.get $rdlen) (i32.const 0x920340)))
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x460000) (i32.const 4))   ;; "root"
    (call $w_entity (i32.const 0x460040) (i32.const 32) (i32.const 0x971000) (local.get $rdlen) (i32.const 0x920340))
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; §4.4 discovery floor grant 1: {handlers:[system/tree], resources:[system/type/*,
  ;; system/handler/*], operations:[get]} — emitted at g_wp.
  (func $emit_grant_floor1
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x461300) (i32.const 8))                          ;; handlers
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x461640) (i32.const 11))    ;; system/tree
    (call $w_text (i32.const 0x461340) (i32.const 9))                          ;; resources
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 2))
    (call $w_text (i32.const 0x461680) (i32.const 13))                         ;; system/type/*
    (call $w_text (i32.const 0x4616c0) (i32.const 16))                         ;; system/handler/*
    (call $w_text (i32.const 0x461380) (i32.const 10))                         ;; operations
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x461700) (i32.const 3)))     ;; get

  ;; §4.4 discovery floor grant 2: {handlers:[system/capability], resources:[],
  ;; operations:[request]} — emitted at g_wp.
  (func $emit_grant_floor2
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x461300) (i32.const 8))                          ;; handlers
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x461740) (i32.const 17))    ;; system/capability
    (call $w_text (i32.const 0x461340) (i32.const 9))                          ;; resources
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 0))
    (call $w_text (i32.const 0x461380) (i32.const 10))                         ;; operations
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x461780) (i32.const 7)))     ;; request

  ;; find the first system/signature entity in the `included` map at $inclp; return its
  ;; entity ptr, or -1. (The authenticate envelope carries exactly one — the client PoP.)
  (func $find_sig (param $inclp i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $kb i32) (local $kl i32) (local $valp i32) (local $t i32) (local $tp i32) (local $tl i32)
    (local.set $p (call $rd_head (local.get $inclp)))
    (if (i32.ne (global.get $g_major) (i32.const 5)) (then (return (i32.const -1))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $kb (call $rd_head (local.get $p)))            ;; key head (33-byte hash)
      (local.set $kl (i32.wrap_i64 (global.get $g_arg)))
      (local.set $valp (i32.add (local.get $kb) (local.get $kl)))
      (local.set $t (call $map_find (local.get $valp) (i32.const 0x460020) (i32.const 4)))   ;; "type"
      (if (i32.ne (local.get $t) (i32.const -1))
        (then
          (local.set $tp (call $rd_head (local.get $t)))
          (local.set $tl (i32.wrap_i64 (global.get $g_arg)))
          (if (call $streq (local.get $tp) (local.get $tl) (i32.const 0x461500) (i32.const 16))   ;; system/signature
            (then (return (local.get $valp))))))
      (local.set $p (call $skip (local.get $valp)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const -1))

  ;; emit the 3-entry `included` map, canonically ordered by the 33-byte content-hash key.
  ;; Table at 0x973000: 3 entries * 24 bytes {key_ptr, type_ptr, type_len, data_ptr, data_len, ch_ptr}.
  (func $emit_incl3
    (local $i i32) (local $j i32) (local $a i32) (local $b i32) (local $t i32) (local $k i32)
    ;; bubble sort by key (mcmp33)
    (block $od (loop $ol
      (br_if $od (i32.ge_u (local.get $i) (i32.const 2)))
      (local.set $j (i32.const 0))
      (block $id (loop $il
        (br_if $id (i32.ge_u (local.get $j) (i32.sub (i32.const 2) (local.get $i))))
        (local.set $a (i32.add (i32.const 0x973000) (i32.mul (local.get $j) (i32.const 24))))
        (local.set $b (i32.add (local.get $a) (i32.const 24)))
        (if (i32.gt_s (call $mcmp33 (i32.load (local.get $a)) (i32.load (local.get $b))) (i32.const 0))
          (then
            (local.set $k (i32.const 0))
            (block $sd (loop $sl
              (br_if $sd (i32.eq (local.get $k) (i32.const 24)))
              (local.set $t (i32.load (i32.add (local.get $a) (local.get $k))))
              (i32.store (i32.add (local.get $a) (local.get $k)) (i32.load (i32.add (local.get $b) (local.get $k))))
              (i32.store (i32.add (local.get $b) (local.get $k)) (local.get $t))
              (local.set $k (i32.add (local.get $k) (i32.const 4)))
              (br $sl)))))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $il)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $ol)))
    ;; emit map(3)
    (call $w_map (i64.const 3))
    (local.set $i (i32.const 0))
    (block $ed (loop $el
      (br_if $ed (i32.eq (local.get $i) (i32.const 3)))
      (local.set $a (i32.add (i32.const 0x973000) (i32.mul (local.get $i) (i32.const 24))))
      (call $w_bstr (i32.load (local.get $a)) (i32.const 33))                           ;; key
      (call $w_entity (i32.load (i32.add (local.get $a) (i32.const 4)))
                      (i32.load (i32.add (local.get $a) (i32.const 8)))
                      (i32.load (i32.add (local.get $a) (i32.const 12)))
                      (i32.load (i32.add (local.get $a) (i32.const 16)))
                      (i32.load (i32.add (local.get $a) (i32.const 20))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $el))))

  ;; store one included-table entry (idx 0..2).
  (func $store_incl (param $idx i32) (param $key i32) (param $tp i32) (param $tl i32) (param $dp i32) (param $dl i32) (param $ch i32)
    (local $e i32) (local.set $e (i32.add (i32.const 0x973000) (i32.mul (local.get $idx) (i32.const 24))))
    (i32.store (local.get $e) (local.get $key))
    (i32.store (i32.add (local.get $e) (i32.const 4))  (local.get $tp))
    (i32.store (i32.add (local.get $e) (i32.const 8))  (local.get $tl))
    (i32.store (i32.add (local.get $e) (i32.const 12)) (local.get $dp))
    (i32.store (i32.add (local.get $e) (i32.const 16)) (local.get $dl))
    (i32.store (i32.add (local.get $e) (i32.const 20)) (local.get $ch)))

  ;; build the authenticate RESPONSE at $out. $in = full envelope, $edp = exec data map,
  ;; $sess = per-connection session {nonce@0, hello_done@32, auth_done@36}. Runs the §4.6 three
  ;; checks (each → 401 with its code) + the §7.1 key_type gate (→ 400), then mints + signs the
  ;; §4.4 floor token and returns a 200 system/capability/grant. Returns out length.
  ;; Scratch: token 0x940000, grant 0x958000, resp 0x959000, sig 0x960000, peer 0x968000;
  ;; hashes 0x920080 auth / 0x9200c0 grantee / 0x920100 tok / 0x920140 grant / 0x920180 sig /
  ;; 0x9201c0 resp ; tok_sig(64) 0x920200 ; derived peer_id 0x972000 (len @0x972100).
  (func $build_auth (param $in i32) (param $out i32) (param $edp i32) (param $rid i32) (param $rlen i32) (param $sess i32) (result i32)
    (local $params i32) (local $pdata i32) (local $kt i32) (local $ktp i32) (local $pk i32) (local $pkp i32)
    (local $nv i32) (local $nptr i32) (local $pidv i32) (local $pidp i32) (local $pidlen i32)
    (local $pdatalen i32) (local $incl i32) (local $sige i32) (local $sigd i32) (local $sigv i32) (local $sigp i32)
    (local $signerv i32) (local $signp i32) (local $ms i64)
    (local $toklen i32) (local $sigdlen i32) (local $grlen i32) (local $rdlen i32) (local $peerlen i32)

    ;; --- parse params / pdata (fail-closed 401 if structurally absent) ---
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))     ;; "params"
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))    ;; "data"
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; --- RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established connection
    ;; must not be re-processed (it would re-verify the same still-cached nonce and re-issue a
    ;; grant). The nonce is documented single-use — reject outright, before any nonce/signature
    ;; work. Does not touch $sess+32 (hello_done), which the hello path owns.
    (if (i32.load (i32.add (local.get $sess) (i32.const 36)))                                     ;; auth_done
      (then (return (call $build_error (local.get $out) (i32.const 0x4617c0) (i32.const 13) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; --- §7.1 key_type gate: present ⇒ must be text "ed25519", else 400 unsupported_key_type ---
    (local.set $kt (call $map_find (local.get $pdata) (i32.const 0x461440) (i32.const 8)))        ;; "key_type"
    (if (i32.ne (local.get $kt) (i32.const -1))
      (then
        (local.set $ktp (call $rd_head (local.get $kt)))
        (if (i32.or (i32.ne (global.get $g_major) (i32.const 3))
                    (i32.or (i32.ne (i32.wrap_i64 (global.get $g_arg)) (i32.const 7))
                            (i32.eqz (call $streq (local.get $ktp) (i32.const 7) (i32.const 0x461600) (i32.const 7)))))
          (then (return (call $build_error (local.get $out) (i32.const 0x461880) (i32.const 20) (i32.const 400) (local.get $rid) (local.get $rlen)))))))

    ;; --- client public_key → $pkp (points into the request buffer) ---
    (local.set $pk (call $map_find (local.get $pdata) (i32.const 0x461080) (i32.const 10)))       ;; "public_key"
    (if (i32.eq (local.get $pk) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $pkp (call $rd_head (local.get $pk)))
    ;; grantee = identity_hash(client pubkey) → 0x9200c0
    (drop (call $identity_hash (local.get $pkp) (i32.const 0x9200c0)))

    ;; --- §4.6 check 1: nonce-echo (401 invalid_nonce) ---
    (if (i32.eqz (i32.load (i32.add (local.get $sess) (i32.const 32))))                            ;; hello not done
      (then (return (call $build_error (local.get $out) (i32.const 0x4617c0) (i32.const 13) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $nv (call $map_find (local.get $pdata) (i32.const 0x4600e0) (i32.const 5)))          ;; "nonce"
    (if (i32.eq (local.get $nv) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x4617c0) (i32.const 13) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $nptr (call $rd_head (local.get $nv)))
    (if (i32.or (i64.ne (global.get $g_arg) (i64.const 32))
                (i32.eqz (call $streq (local.get $nptr) (i32.const 32) (local.get $sess) (i32.const 32))))
      (then (return (call $build_error (local.get $out) (i32.const 0x4617c0) (i32.const 13) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; --- §4.6 check 3 (identity-binding): base58(pubkey) == params.peer_id (401 identity_mismatch) ---
    (drop (call $format_peer_id (local.get $pkp) (i32.const 0x972000) (i32.const 128) (i32.const 0x972100)))
    (local.set $pidv (call $map_find (local.get $pdata) (i32.const 0x4600f0) (i32.const 7)))        ;; "peer_id"
    (if (i32.eq (local.get $pidv) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461840) (i32.const 17) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $pidp (call $rd_head (local.get $pidv)))
    (local.set $pidlen (i32.wrap_i64 (global.get $g_arg)))
    (if (i32.or (i32.ne (local.get $pidlen) (i32.load (i32.const 0x972100)))
                (i32.eqz (call $streq (local.get $pidp) (local.get $pidlen) (i32.const 0x972000) (i32.load (i32.const 0x972100)))))
      (then (return (call $build_error (local.get $out) (i32.const 0x461840) (i32.const 17) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; --- §4.6 check 2 (proof-of-possession): verify the included signature over auth_hash ---
    (local.set $pdatalen (i32.sub (call $skip (local.get $pdata)) (local.get $pdata)))
    (drop (call $content_hash (i32.const 0x461480) (i32.const 36) (local.get $pdata) (local.get $pdatalen) (i32.const 0x920080)))  ;; auth_hash
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))           ;; "included"
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $sige (call $find_sig (local.get $incl)))
    (if (i32.eq (local.get $sige) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $sigd (call $map_find (local.get $sige) (i32.const 0x460010) (i32.const 4)))          ;; "data"
    (if (i32.eq (local.get $sigd) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $sigv (call $map_find (local.get $sigd) (i32.const 0x4610c0) (i32.const 9)))          ;; "signature"
    (if (i32.eq (local.get $sigv) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $sigp (call $rd_head (local.get $sigv)))
    (if (call $ed_verify (local.get $pkp) (i32.const 0x920080) (i32.const 33) (local.get $sigp))     ;; nonzero ⇒ invalid
      (then (return (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; --- §3.5 signer check: signature.signer == client identity_hash (401 identity_mismatch) ---
    (local.set $signerv (call $map_find (local.get $sigd) (i32.const 0x461100) (i32.const 6)))       ;; "signer"
    (if (i32.eq (local.get $signerv) (i32.const -1)) (then (return (call $build_error (local.get $out) (i32.const 0x461840) (i32.const 17) (i32.const 401) (local.get $rid) (local.get $rlen)))))
    (local.set $signp (call $rd_head (local.get $signerv)))
    (if (i32.eqz (call $streq (local.get $signp) (i32.const 33) (i32.const 0x9200c0) (i32.const 33)))
      (then (return (call $build_error (local.get $out) (i32.const 0x461840) (i32.const 17) (i32.const 401) (local.get $rid) (local.get $rlen)))))

    ;; ======================= verification passed — mint =======================
    (i32.store (i32.add (local.get $sess) (i32.const 36)) (i32.const 1))                          ;; auth_done = 1 (RT-6)
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))

    ;; token data {grants:[floor1,floor2(,*)], grantee, granter, created_at} @0x940000
    (global.set $g_wp (i32.const 0x940000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x4611c0) (i32.const 6))                                             ;; "grants"
    (if (global.get $g_open)                                                                     ;; --debug-open-grants → append *
      (then (call $w_array (i64.const 3)) (call $emit_grant_floor1) (call $emit_grant_floor2) (call $emit_grant_star))
      (else (call $w_array (i64.const 2)) (call $emit_grant_floor1) (call $emit_grant_floor2)))
    (call $w_text (i32.const 0x461200) (i32.const 7))  (call $w_bstr (i32.const 0x9200c0) (i32.const 33))   ;; "grantee"
    (call $w_text (i32.const 0x461240) (i32.const 7))  (call $w_bstr (i32.const 0x440000) (i32.const 33))   ;; "granter" = my idhash
    (call $w_text (i32.const 0x461280) (i32.const 10)) (call $w_uint (local.get $ms))                       ;; "created_at"
    (local.set $toklen (i32.sub (global.get $g_wp) (i32.const 0x940000)))
    (drop (call $content_hash (i32.const 0x461540) (i32.const 23) (i32.const 0x940000) (local.get $toklen) (i32.const 0x920100)))  ;; tok_ch
    (drop (call $ed_sign (i32.const 0x420000) (i32.const 0x920100) (i32.const 33) (i32.const 0x920200)))   ;; tok_sig over tok_ch

    ;; signature entity data {signer,target,algorithm,signature} @0x960000
    (global.set $g_wp (i32.const 0x960000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x461100) (i32.const 6))  (call $w_bstr (i32.const 0x440000) (i32.const 33))   ;; "signer" = my idhash
    (call $w_text (i32.const 0x461140) (i32.const 6))  (call $w_bstr (i32.const 0x920100) (i32.const 33))   ;; "target" = tok_ch
    (call $w_text (i32.const 0x461180) (i32.const 9))  (call $w_text (i32.const 0x461600) (i32.const 7))    ;; "algorithm":"ed25519"
    (call $w_text (i32.const 0x4610c0) (i32.const 9))  (call $w_bstr (i32.const 0x920200) (i32.const 64))   ;; "signature"
    (local.set $sigdlen (i32.sub (global.get $g_wp) (i32.const 0x960000)))
    (drop (call $content_hash (i32.const 0x461500) (i32.const 16) (i32.const 0x960000) (local.get $sigdlen) (i32.const 0x920180)))  ;; sig_ch

    ;; grant result data {token: tok_ch} @0x958000
    (global.set $g_wp (i32.const 0x958000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4612c0) (i32.const 5)) (call $w_bstr (i32.const 0x920100) (i32.const 33))    ;; "token"
    (local.set $grlen (i32.sub (global.get $g_wp) (i32.const 0x958000)))
    (drop (call $content_hash (i32.const 0x461580) (i32.const 23) (i32.const 0x958000) (local.get $grlen) (i32.const 0x920140)))    ;; grant_ch

    ;; my peer entity data {key_type, public_key} @0x968000
    (local.set $peerlen (call $build_peer_data (i32.const 0x420100) (i32.const 0x968000)))

    ;; response data {result:<grant entity>, status:200, request_id} @0x959000
    (global.set $g_wp (i32.const 0x959000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))                                                       ;; "result"
    (call $w_entity (i32.const 0x461580) (i32.const 23) (i32.const 0x958000) (local.get $grlen) (i32.const 0x920140))
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (i64.const 200))                       ;; "status"
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (local.get $rid) (local.get $rlen))    ;; "request_id"
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x959000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x959000) (local.get $rdlen) (i32.const 0x9201c0)))   ;; resp_ch

    ;; envelope {root:<resp entity>, included:{token, peer, sig} sorted} @out
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x460000) (i32.const 4))                                                       ;; "root"
    (call $w_entity (i32.const 0x460040) (i32.const 32) (i32.const 0x959000) (local.get $rdlen) (i32.const 0x9201c0))
    (call $w_text (i32.const 0x461040) (i32.const 8))                                                       ;; "included"
    (call $store_incl (i32.const 0) (i32.const 0x920100) (i32.const 0x461540) (i32.const 23) (i32.const 0x940000) (local.get $toklen) (i32.const 0x920100))  ;; token
    (call $store_incl (i32.const 1) (i32.const 0x440000) (i32.const 0x4614c0) (i32.const 11) (i32.const 0x968000) (local.get $peerlen) (i32.const 0x440000)) ;; my peer
    (call $store_incl (i32.const 2) (i32.const 0x920180) (i32.const 0x461500) (i32.const 16) (i32.const 0x960000) (local.get $sigdlen) (i32.const 0x920180)) ;; signature
    (call $emit_incl3)
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; ===================== tree GET: store + §5.2 authority (increment 5a) =====================
  (global $arena  (mut i32) (i32.const 0xA10000))   ;; store entity arena cursor
  (global $s_blen (mut i32) (i32.const 0))          ;; last store_get blob length
  (global $g_hptr (mut i32) (i32.const 0))          ;; request handler (derive_handler)
  (global $g_hlen (mut i32) (i32.const 0))
  ;; §5.2 extract_peer target_peer (derive_handler): the EXECUTE uri's own peer segment when it
  ;; is peer-id-shaped, else local_peer_id — consumed by $peers_scope_ok.
  (global $g_tpp   (mut i32) (i32.const 0))
  (global $g_tplen (mut i32) (i32.const 0))
  (global $g_rtp   (mut i32) (i32.const 0))         ;; register/unregister: resource system/handler/{pattern}
  (global $g_rtlen (mut i32) (i32.const 0))
  (global $g_patp   (mut i32) (i32.const 0))        ;; register/unregister: {pattern} tail
  (global $g_patlen (mut i32) (i32.const 0))
  ;; --debug-open-grants: the degenerate seed policy (default→*). When set (by host arg parsing
  ;; via $set_open), authenticate mints an extra {handlers/resources/operations: include:["*"]}
  ;; grant into the connection token, so grant-gated core ops (capability configure/revoke, tree
  ;; put, handler register) authorize. NOT a verdict bypass — the authz DENY tests present their
  ;; own restricted caps and still 403; only the peer-minted connection token gains the * grant.
  (global $g_open (mut i32) (i32.const 0))
  (func $set_open (export "set_open") (param $v i32) (global.set $g_open (local.get $v)))

  ;; §7a conformance-handler state. g_validate: --validate armed. g_ei_ctr: monotonic outbound
  ;; reentry request_id counter (pending-table key). Pending reentry table @0x990000: 16 slots *
  ;; 128B { active@0, ei_len@4, ei@8(16), di_len@40, di@44(72) } — maps an outbound echo's
  ;; request_id (Ei) to the dispatch-outbound request_id (Di) whose reply is deferred until Ei's
  ;; EXECUTE_RESPONSE returns on the same connection (§7a.2a same-connection reentry).
  (global $g_validate (mut i32) (i32.const 0))
  (global $g_ei_ctr (mut i32) (i32.const 0))
  (func $set_validate (export "set_validate") (param $v i32)
    (global.set $g_validate (local.get $v))
    (if (local.get $v) (then (call $publish_validate))))

  ;; build + store one system/handler/interface entity {name:pattern, pattern, operations:{<op>:
  ;; {input_type:primitive/any, output_type:primitive/any}}} at interface path [ip,ipl].
  (func $pub_iface (param $pat i32) (param $patl i32) (param $ip i32) (param $ipl i32) (param $op i32) (param $opl i32)
    (local $dlen i32) (local $blen i32)
    (global.set $g_wp (i32.const 0x982000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x462540) (i32.const 4))  (call $w_text (local.get $pat) (local.get $patl))   ;; name
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (local.get $pat) (local.get $patl))   ;; pattern
    (call $w_text (i32.const 0x461380) (i32.const 10))                                                     ;; operations
    (call $w_map (i64.const 1))
    (call $w_text (local.get $op) (local.get $opl))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4625c0) (i32.const 10)) (call $w_text (i32.const 0x462840) (i32.const 13))  ;; input_type:primitive/any
    (call $w_text (i32.const 0x462600) (i32.const 11)) (call $w_text (i32.const 0x462840) (i32.const 13))  ;; output_type:primitive/any
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x982000)))
    (drop (call $content_hash (i32.const 0x462640) (i32.const 24) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985000)))
    (global.set $g_wp (i32.const 0x983000))
    (call $w_entity (i32.const 0x462640) (i32.const 24) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985000))
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x983000)))
    (call $store_put (local.get $ip) (local.get $ipl) (i32.const 0x983000) (local.get $blen)))

  ;; publish the two §7a interface entities so a validator's HasConformanceHandlers probe
  ;; (tree-get system/handler/system/validate/dispatch-outbound) resolves them.
  (func $publish_validate
    (call $pub_iface (i32.const 0x466a00) (i32.const 20) (i32.const 0x466a80) (i32.const 35) (i32.const 0x466b20) (i32.const 4))   ;; echo:echo
    (call $pub_iface (i32.const 0x466a40) (i32.const 33) (i32.const 0x466ac0) (i32.const 48) (i32.const 0x466b00) (i32.const 8)))  ;; dispatch-outbound:dispatch

  ;; emit an n-entry `included` map (n≥1), canonically ordered by 33-byte content-hash key.
  ;; Table at 0x973000 (n entries * 24 bytes), same layout as store_incl.
  (func $emit_incl_n (param $n i32)
    (local $i i32) (local $j i32) (local $a i32) (local $b i32) (local $t i32) (local $k i32)
    (block $od (loop $ol
      (br_if $od (i32.ge_u (local.get $i) (i32.sub (local.get $n) (i32.const 1))))
      (local.set $j (i32.const 0))
      (block $id (loop $il
        (br_if $id (i32.ge_u (local.get $j) (i32.sub (i32.sub (local.get $n) (i32.const 1)) (local.get $i))))
        (local.set $a (i32.add (i32.const 0x973000) (i32.mul (local.get $j) (i32.const 24))))
        (local.set $b (i32.add (local.get $a) (i32.const 24)))
        (if (i32.gt_s (call $mcmp33 (i32.load (local.get $a)) (i32.load (local.get $b))) (i32.const 0))
          (then
            (local.set $k (i32.const 0))
            (block $sd (loop $sl
              (br_if $sd (i32.eq (local.get $k) (i32.const 24)))
              (local.set $t (i32.load (i32.add (local.get $a) (local.get $k))))
              (i32.store (i32.add (local.get $a) (local.get $k)) (i32.load (i32.add (local.get $b) (local.get $k))))
              (i32.store (i32.add (local.get $b) (local.get $k)) (local.get $t))
              (local.set $k (i32.add (local.get $k) (i32.const 4)))
              (br $sl)))))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $il)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $ol)))
    (call $w_map (i64.extend_i32_u (local.get $n)))
    (local.set $i (i32.const 0))
    (block $ed (loop $el
      (br_if $ed (i32.eq (local.get $i) (local.get $n)))
      (local.set $a (i32.add (i32.const 0x973000) (i32.mul (local.get $i) (i32.const 24))))
      (call $w_bstr (i32.load (local.get $a)) (i32.const 33))
      (call $w_entity (i32.load (i32.add (local.get $a) (i32.const 4)))
                      (i32.load (i32.add (local.get $a) (i32.const 8)))
                      (i32.load (i32.add (local.get $a) (i32.const 12)))
                      (i32.load (i32.add (local.get $a) (i32.const 16)))
                      (i32.load (i32.add (local.get $a) (i32.const 20))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $el))))

  ;; stage a verbatim nested entity ({data,type,content_hash} map at $ent, content_hash 33B at $ch)
  ;; into included slot $idx — reproduced byte-identically (canonical data<type<content_hash).
  (func $store_incl_ent (param $idx i32) (param $ent i32) (param $ch i32)
    (local $tp i32) (local $tl i32) (local $dp i32) (local $dl i32)
    (local.set $tp (call $rd_head (call $map_find (local.get $ent) (i32.const 0x460020) (i32.const 4))))   ;; type
    (local.set $tl (i32.wrap_i64 (global.get $g_arg)))
    (local.set $dp (call $map_find (local.get $ent) (i32.const 0x460010) (i32.const 4)))                   ;; data (value ptr)
    (local.set $dl (i32.sub (call $skip (local.get $dp)) (local.get $dp)))
    (call $store_incl (local.get $idx) (local.get $ch) (local.get $tp) (local.get $tl) (local.get $dp) (local.get $dl) (local.get $ch)))

  ;; write the next outbound reentry request_id "wro-XXXXXXXX" (8 hex of g_ei_ctr) to $dst; return
  ;; its length (12). Monotonic → unique per in-flight outbound echo (the pending-table key).
  (func $w_ei_rid (param $dst i32) (result i32)
    (local $v i32) (local $i i32)
    (i32.store8 (local.get $dst) (i32.const 0x77))                            ;; 'w'
    (i32.store8 (i32.add (local.get $dst) (i32.const 1)) (i32.const 0x72))    ;; 'r'
    (i32.store8 (i32.add (local.get $dst) (i32.const 2)) (i32.const 0x6f))    ;; 'o'
    (i32.store8 (i32.add (local.get $dst) (i32.const 3)) (i32.const 0x2d))    ;; '-'
    (local.set $v (global.get $g_ei_ctr))
    (global.set $g_ei_ctr (i32.add (local.get $v) (i32.const 1)))
    (block $d (loop $l
      (br_if $d (i32.eq (local.get $i) (i32.const 8)))
      (i32.store8 (i32.add (i32.add (local.get $dst) (i32.const 4)) (local.get $i))
        (i32.load8_u (i32.add (i32.const 0x462bc0)
          (i32.and (i32.shr_u (local.get $v) (i32.sub (i32.const 28) (i32.mul (local.get $i) (i32.const 4)))) (i32.const 0xf)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))
    (i32.const 12))

  ;; pending reentry table (0x990000, 16 slots * 128B). add: claim a free slot (Ei→Di).
  (func $pend_add (param $ei i32) (param $eil i32) (param $di i32) (param $dil i32)
    (local $i i32) (local $e i32)
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (i32.const 16)))
      (local.set $e (i32.add (i32.const 0x990000) (i32.mul (local.get $i) (i32.const 128))))
      (if (i32.eqz (i32.load (local.get $e)))
        (then
          (i32.store (local.get $e) (i32.const 1))
          (i32.store (i32.add (local.get $e) (i32.const 4)) (local.get $eil))
          (memory.copy (i32.add (local.get $e) (i32.const 8)) (local.get $ei) (local.get $eil))
          (i32.store (i32.add (local.get $e) (i32.const 40)) (local.get $dil))
          (memory.copy (i32.add (local.get $e) (i32.const 44)) (local.get $di) (local.get $dil))
          (return)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L))))

  ;; find + claim the pending entry whose Ei matches [ei,eil]; return entry ptr (di@+44, dil@+40)
  ;; and mark it free, or 0 if none.
  (func $pend_take (param $ei i32) (param $eil i32) (result i32)
    (local $i i32) (local $e i32)
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (i32.const 16)))
      (local.set $e (i32.add (i32.const 0x990000) (i32.mul (local.get $i) (i32.const 128))))
      (if (i32.and (i32.load (local.get $e))
                   (i32.and (i32.eq (i32.load (i32.add (local.get $e) (i32.const 4))) (local.get $eil))
                            (call $streq (i32.add (local.get $e) (i32.const 8)) (local.get $eil) (local.get $ei) (local.get $eil))))
        (then (i32.store (local.get $e) (i32.const 0)) (return (local.get $e))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 0))
  ;; §1.4 universal address space: the canonical store key. A peer-relative path (no leading '/')
  ;; is the local namespace and is its own canonical key; an absolute '/{local_peer_id}/P' is the
  ;; SAME local key (strip the prefix → peer-relative P); an absolute '/{other_peer}/P' is a
  ;; DISTINCT foreign namespace and stays verbatim. $canon_path sets $g_cpp/$g_cplen accordingly.
  (global $g_cpp   (mut i32) (i32.const 0))
  (global $g_cplen (mut i32) (i32.const 0))
  (global $g_chp   (mut i32) (i32.const 0))     ;; listing: immediate-child segment of a store key
  (global $g_chlen (mut i32) (i32.const 0))
  (func $canon_path (param $pin i32) (param $plen i32)
    (local $pidlen i32) (local $pfx i32)
    (global.set $g_cpp (local.get $pin))
    (global.set $g_cplen (local.get $plen))
    (if (i32.eqz (local.get $plen)) (then (return)))
    (if (i32.ne (i32.load8_u (local.get $pin)) (i32.const 0x2f)) (then (return)))   ;; peer-relative → itself
    (local.set $pidlen (i32.load (i32.const 0x4202F0)))                             ;; local peer_id length
    (local.set $pfx (i32.add (local.get $pidlen) (i32.const 2)))                    ;; "/" + pid + "/"
    (if (i32.lt_u (local.get $plen) (local.get $pfx)) (then (return)))              ;; too short to be local-absolute
    (if (i32.eqz (call $streq (i32.add (local.get $pin) (i32.const 1)) (local.get $pidlen) (i32.const 0x420200) (local.get $pidlen))) (then (return)))  ;; foreign
    (if (i32.ne (i32.load8_u (i32.add (local.get $pin) (i32.add (local.get $pidlen) (i32.const 1)))) (i32.const 0x2f)) (then (return)))
    (global.set $g_cpp (i32.add (local.get $pin) (local.get $pfx)))                 ;; strip "/{local}/" → peer-relative
    (global.set $g_cplen (i32.sub (local.get $plen) (local.get $pfx))))
  ;; a wildcard grant {handlers:{include:[*]}, resources:{include:[*]}, operations:{include:[*]}},
  ;; canonically ordered (handlers<resources<operations by key length). Emitted at g_wp.
  (func $emit_grant_star
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x461300) (i32.const 8))                                     ;; handlers
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))         ;; include
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x4623c0) (i32.const 1))       ;; "*"
    (call $w_text (i32.const 0x461340) (i32.const 9))                                     ;; resources
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 2)) (call $w_text (i32.const 0x4623c0) (i32.const 1))        ;; "*" (local namespace)
    (call $w_text (i32.const 0x4669e0) (i32.const 4))                                     ;; "/*/*" (any peer namespace)
    (call $w_text (i32.const 0x461380) (i32.const 10))                                    ;; operations
    (call $w_map (i64.const 1)) (call $w_text (i32.const 0x4613c0) (i32.const 7))
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x4623c0) (i32.const 1)))

  ;; error-response shorthands (build the coded EXECUTE_RESPONSE at $out, return its length).
  (func $err_authfail (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x461800) (i32.const 21) (i32.const 401) (local.get $rid) (local.get $rlen)))
  (func $err_capden (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462240) (i32.const 17) (i32.const 403) (local.get $rid) (local.get $rlen)))
  (func $err_unresg (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462340) (i32.const 20) (i32.const 401) (local.get $rid) (local.get $rlen)))
  (func $err_404 (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462300) (i32.const 9) (i32.const 404) (local.get $rid) (local.get $rlen)))
  ;; §4.10(a) 413 payload_too_large. Emitted for an over-`max_payload` inbound frame after the
  ;; body is drained; the connection stays open (host keeps serving). The over-size condition is
  ;; detected before the envelope is parsed, so no request_id is available — best-effort empty rid
  ;; (the spec's MAY path; §6.11(c) deadline backstops the caller). Exported for host.wat.
  (func $emit_413 (export "emit_413") (param $out i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462420) (i32.const 17) (i32.const 413) (i32.const 0x462400) (i32.const 0)))

  ;; --- store: index @0xA00000 {count i32; entries@+0x10 = 16B {path,plen,blob,blen}} ---
  (func $store_add (param $pp i32) (param $pl i32) (param $bp i32) (param $bl i32)
    (local $c i32) (local $e i32)
    (local.set $c (i32.load (i32.const 0xA00000)))
    (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $c) (i32.const 16))))
    (i32.store (local.get $e) (local.get $pp))
    (i32.store (i32.add (local.get $e) (i32.const 4)) (local.get $pl))
    (i32.store (i32.add (local.get $e) (i32.const 8)) (local.get $bp))
    (i32.store (i32.add (local.get $e) (i32.const 12)) (local.get $bl))
    (i32.store (i32.const 0xA00000) (i32.add (local.get $c) (i32.const 1))))

  (func $store_get (param $tp i32) (param $tlen i32) (result i32)
    (local $c i32) (local $i i32) (local $e i32)
    (local.set $c (i32.load (i32.const 0xA00000)))
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (local.get $c)))
      (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $i) (i32.const 16))))
      (if (i32.eq (i32.load (i32.add (local.get $e) (i32.const 4))) (local.get $tlen))
        (then (if (call $streq (i32.load (local.get $e)) (local.get $tlen) (local.get $tp) (local.get $tlen))
          (then
            (global.set $s_blen (i32.load (i32.add (local.get $e) (i32.const 12))))
            (return (i32.load (i32.add (local.get $e) (i32.const 8))))))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 0))

  ;; write store (A-ASM-011): persist an entity blob at a canonical path across requests.
  ;; Copies both path and blob out of the (per-frame) request buffer into the persistent arena
  ;; so $store_get finds them on any later request. Overwrites an existing binding in place.
  (func $store_put (param $pp i32) (param $pl i32) (param $bp i32) (param $bl i32)
    (local $c i32) (local $i i32) (local $e i32) (local $pd i32) (local $bd i32)
    (local.set $c (i32.load (i32.const 0xA00000)))
    (global.set $g_wp (global.get $arena))
    ;; scan for an existing entry with this path → overwrite its blob
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (local.get $c)))
      (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $i) (i32.const 16))))
      (if (i32.and (i32.eq (i32.load (i32.add (local.get $e) (i32.const 4))) (local.get $pl))
                   (call $streq (i32.load (local.get $e)) (local.get $pl) (local.get $pp) (local.get $pl)))
        (then
          (local.set $bd (global.get $g_wp))
          (call $w_bytes (local.get $bp) (local.get $bl))
          (global.set $arena (global.get $g_wp))
          (i32.store (i32.add (local.get $e) (i32.const 8))  (local.get $bd))
          (i32.store (i32.add (local.get $e) (i32.const 12)) (local.get $bl))
          (return)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    ;; new binding: append path then blob to the arena, then index it
    (local.set $pd (global.get $g_wp))
    (call $w_bytes (local.get $pp) (local.get $pl))
    (local.set $bd (global.get $g_wp))
    (call $w_bytes (local.get $bp) (local.get $bl))
    (global.set $arena (global.get $g_wp))
    (call $store_add (local.get $pd) (local.get $pl) (local.get $bd) (local.get $bl)))

  ;; hex-encode 33 bytes at $src into 66 ASCII chars at $dst (lowercase; asm `hexenc`).
  (func $hexenc (param $src i32) (param $dst i32)
    (local $i i32) (local $b i32)
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (i32.const 33)))
      (local.set $b (i32.load8_u (i32.add (local.get $src) (local.get $i))))
      (i32.store8 (i32.add (local.get $dst) (i32.mul (local.get $i) (i32.const 2)))
                  (i32.load8_u (i32.add (i32.const 0x462bc0) (i32.shr_u (local.get $b) (i32.const 4)))))
      (i32.store8 (i32.add (i32.add (local.get $dst) (i32.mul (local.get $i) (i32.const 2))) (i32.const 1))
                  (i32.load8_u (i32.add (i32.const 0x462bc0) (i32.and (local.get $b) (i32.const 0xf)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L))))

  ;; build "system/capability/revocations/<hex(cap)>" at 0x978000 → returns its length (96).
  (func $revoc_path (param $cap i32) (result i32)
    (call $hexenc (local.get $cap) (i32.const 0x978100))
    (global.set $g_wp (i32.const 0x978000))
    (call $w_bytes (i32.const 0x462b00) (i32.const 30))   ;; prefix
    (call $w_bytes (i32.const 0x978100) (i32.const 66))   ;; hex
    (i32.sub (global.get $g_wp) (i32.const 0x978000)))

  ;; hash data@0xA08000 (len $dlen) under $type, emit the full entity into the arena, index it.
  (func $finish_entity (param $pp i32) (param $pl i32) (param $tp i32) (param $tl i32) (param $dlen i32)
    (local $ep i32) (local $el i32)
    (drop (call $content_hash (local.get $tp) (local.get $tl) (i32.const 0xA08000) (local.get $dlen) (i32.const 0xA09000)))
    (local.set $ep (global.get $arena))
    (global.set $g_wp (global.get $arena))
    (call $w_entity (local.get $tp) (local.get $tl) (i32.const 0xA08000) (local.get $dlen) (i32.const 0xA09000))
    (local.set $el (i32.sub (global.get $g_wp) (local.get $ep)))
    (global.set $arena (global.get $g_wp))
    (call $store_add (local.get $pp) (local.get $pl) (local.get $ep) (local.get $el)))

  ;; emit  <op>: {input_type:"primitive/any", output_type:"primitive/any"}
  (func $wop (param $op i32) (param $oplen i32)
    (call $w_text (local.get $op) (local.get $oplen))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4625c0) (i32.const 10)) (call $w_text (i32.const 0x462840) (i32.const 13))   ;; input_type
    (call $w_text (i32.const 0x462600) (i32.const 11)) (call $w_text (i32.const 0x462840) (i32.const 13)))  ;; output_type

  ;; publish the three core handler-interface entities (§6.2) into the store.
  (func $store_init (export "store_init")
    (i32.store (i32.const 0xA00000) (i32.const 0))
    (global.set $arena (i32.const 0xA10000))
    ;; connect: {name, pattern, operations:{hello, authenticate}}
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x462540) (i32.const 4))  (call $w_text (i32.const 0x462680) (i32.const 7))    ;; name: connect
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (i32.const 0x462740) (i32.const 23))   ;; pattern
    (call $w_text (i32.const 0x461380) (i32.const 10)) (call $w_map (i64.const 2))                          ;; operations
    (call $wop (i32.const 0x4600d0) (i32.const 5))   (call $wop (i32.const 0x4618c0) (i32.const 12))        ;; hello, authenticate
    (call $finish_entity (i32.const 0x462440) (i32.const 38) (i32.const 0x462640) (i32.const 24) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; tree: {name, pattern, operations:{get, put, diff, merge, extract, snapshot}} — full §9 set
    ;; so operations_match passes under both --profile full and core (core scores just get/put).
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x462540) (i32.const 4))  (call $w_text (i32.const 0x4626c0) (i32.const 4))    ;; name: tree
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (i32.const 0x461640) (i32.const 11))   ;; pattern: system/tree
    (call $w_text (i32.const 0x461380) (i32.const 10)) (call $w_map (i64.const 6))
    (call $wop (i32.const 0x462200) (i32.const 3))   (call $wop (i32.const 0x462780) (i32.const 3))         ;; get, put
    (call $wop (i32.const 0x462980) (i32.const 4))   (call $wop (i32.const 0x4629c0) (i32.const 5))         ;; diff, merge
    (call $wop (i32.const 0x462a00) (i32.const 7))   (call $wop (i32.const 0x462a40) (i32.const 8))         ;; extract, snapshot
    (call $finish_entity (i32.const 0x462480) (i32.const 26) (i32.const 0x462640) (i32.const 24) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; capability: {name, pattern, operations:{revoke, request, delegate}}
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x462540) (i32.const 4))  (call $w_text (i32.const 0x462700) (i32.const 10))   ;; name: capability
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (i32.const 0x461740) (i32.const 17))   ;; pattern: system/capability
    (call $w_text (i32.const 0x461380) (i32.const 10)) (call $w_map (i64.const 3))
    (call $wop (i32.const 0x462800) (i32.const 6))   (call $wop (i32.const 0x461780) (i32.const 7))  (call $wop (i32.const 0x4627c0) (i32.const 8))  ;; revoke, request, delegate
    (call $finish_entity (i32.const 0x4624c0) (i32.const 32) (i32.const 0x462640) (i32.const 24) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; ===== §6.2 N2/N5 handler dispatch entities: a system/handler entity at each core pattern
    ;; path, its `interface` field pointing at the matching system/handler/interface index entry.
    ;; Dispatch (§6.6) finds these by type; the interface field links dispatch target → public
    ;; contract (handler_{connect,tree,capability}_dispatch_type / _interface_ref). =====
    (global.set $g_wp (i32.const 0xA08000))       ;; system/protocol/connect handler
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4668b0) (i32.const 9)) (call $w_text (i32.const 0x462440) (i32.const 38))  ;; interface: system/handler/system/protocol/connect
    (call $finish_entity (i32.const 0x462740) (i32.const 23) (i32.const 0x466800) (i32.const 14) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    (global.set $g_wp (i32.const 0xA08000))       ;; system/tree handler
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4668b0) (i32.const 9)) (call $w_text (i32.const 0x462480) (i32.const 26))  ;; interface: system/handler/system/tree
    (call $finish_entity (i32.const 0x461640) (i32.const 11) (i32.const 0x466800) (i32.const 14) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    (global.set $g_wp (i32.const 0xA08000))       ;; system/capability handler
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4668b0) (i32.const 9)) (call $w_text (i32.const 0x4624c0) (i32.const 32))  ;; interface: system/handler/system/capability
    (call $finish_entity (i32.const 0x461740) (i32.const 17) (i32.const 0x466800) (i32.const 14) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; ===== §9.5 Core Type Floor: publish the 53 system/type/* entities =====
    ;; --- system/type/core/entity ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x4630c0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $w_text (i32.const 0x463140) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x4631c0) (i32.const 12))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $finish_entity (i32.const 0x463040) (i32.const 23) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/core/envelope ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463280) (i32.const 13))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4632c0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x463300) (i32.const 8))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x4650c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x463240) (i32.const 25) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/entity ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463380) (i32.const 6))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4630c0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $w_text (i32.const 0x463140) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x463340) (i32.const 18) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/any ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $finish_entity (i32.const 0x4633c0) (i32.const 25) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/bool ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463440) (i32.const 14))
    (call $finish_entity (i32.const 0x463400) (i32.const 26) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/bytes ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $finish_entity (i32.const 0x463480) (i32.const 27) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/float ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463540) (i32.const 15))
    (call $finish_entity (i32.const 0x463500) (i32.const 27) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/int ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x4635c0) (i32.const 13))
    (call $finish_entity (i32.const 0x463580) (i32.const 25) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/null ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463640) (i32.const 14))
    (call $finish_entity (i32.const 0x463600) (i32.const 26) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/string ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x463680) (i32.const 28) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/primitive/uint ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x4636c0) (i32.const 26) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/bounds ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463780) (i32.const 13))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x4637c0) (i32.const 3))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x463800) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x463840) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4638c0) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x463900) (i32.const 13))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x463940) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x463740) (i32.const 25) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/delegate-request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x4639c0) (i32.const 34))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x463a00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x463a80) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x463ac0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x463980) (i32.const 46) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/delegation-caveats ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463b40) (i32.const 36))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x463b80) (i32.const 13))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463440) (i32.const 14))
    (call $w_text (i32.const 0x463bc0) (i32.const 18))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x463c00) (i32.const 20))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x463b00) (i32.const 48) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/grant ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463c80) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x463cc0) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $finish_entity (i32.const 0x463c40) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/grant-entry ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x463d40) (i32.const 5))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463d80) (i32.const 26))
    (call $w_text (i32.const 0x463dc0) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463e00) (i32.const 28))
    (call $w_text (i32.const 0x463e40) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463e00) (i32.const 28))
    (call $w_text (i32.const 0x463e80) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x463ec0) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463d80) (i32.const 26))
    (call $w_text (i32.const 0x463f00) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x463d00) (i32.const 41) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/id-scope ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463d80) (i32.const 26))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x463f80) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x463fc0) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x463f40) (i32.const 38) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/multi-granter ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464040) (i32.const 31))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464080) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x4640c0) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x464000) (i32.const 43) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/path-scope ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463e00) (i32.const 28))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x463f80) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x463fc0) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $finish_entity (i32.const 0x464100) (i32.const 40) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/policy-entry ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464180) (i32.const 30))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x4641c0) (i32.const 5))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x463a00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x463ac0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x464200) (i32.const 12))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x464140) (i32.const 42) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464280) (i32.const 25))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x463a00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x463ac0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x464240) (i32.const 37) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/revocation ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464300) (i32.const 28))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x463cc0) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x464340) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x464380) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x4642c0) (i32.const 40) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/revoke-request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464400) (i32.const 32))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x463cc0) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x464340) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x4643c0) (i32.const 44) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/capability/token ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464480) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 9))
    (call $w_text (i32.const 0x463a00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x463a80) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x4644c0) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x464500) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466600) (i32.const 8))
    (call $w_array (i64.const 2))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464040) (i32.const 31))
    (call $w_text (i32.const 0x464540) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x464580) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x4645c0) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x464600) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464640) (i32.const 22))
    (call $w_text (i32.const 0x464680) (i32.const 18))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463b40) (i32.const 36))
    (call $finish_entity (i32.const 0x464440) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/deletion-marker ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464700) (i32.const 22))
    (call $finish_entity (i32.const 0x4646c0) (i32.const 34) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/delivery-spec ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464780) (i32.const 20))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4647c0) (i32.const 3))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x464800) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x464740) (i32.const 32) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/envelope ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464880) (i32.const 15))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x463280) (i32.const 13))
    (call $finish_entity (i32.const 0x464840) (i32.const 27) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464900) (i32.const 14))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x464940) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x464980) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4649c0) (i32.const 14))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x464a00) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $finish_entity (i32.const 0x4648c0) (i32.const 26) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler/interface ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464a80) (i32.const 24))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x464ac0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x464b00) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x463ec0) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464b40) (i32.const 29))
    (call $finish_entity (i32.const 0x464a40) (i32.const 36) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler/manifest ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464bc0) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x464ac0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x464b00) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x464980) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x463ec0) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464b40) (i32.const 29))
    (call $w_text (i32.const 0x4649c0) (i32.const 14))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x464a00) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x464a80) (i32.const 24))
    (call $finish_entity (i32.const 0x464b80) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler/operation-spec ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464b40) (i32.const 29))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464c40) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x464cc0) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $finish_entity (i32.const 0x464c00) (i32.const 41) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler/register-request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464d40) (i32.const 31))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x464d80) (i32.const 5))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463000) (i32.const 11))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x464dc0) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464bc0) (i32.const 23))
    (call $w_text (i32.const 0x464e00) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463a40) (i32.const 29))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x464d00) (i32.const 43) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/handler/register-result ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464e80) (i32.const 30))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ec0) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464480) (i32.const 23))
    (call $w_text (i32.const 0x464b00) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $finish_entity (i32.const 0x464e40) (i32.const 42) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/hash ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464f80) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $w_text (i32.const 0x464f40) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x466640) (i32.const 9))
    (call $w_uint (i64.const 1))
    (call $w_text (i32.const 0x466380) (i32.const 6))
    (call $w_array (i64.const 2))
    (call $w_text (i32.const 0x464f40) (i32.const 11))
    (call $w_text (i32.const 0x464f80) (i32.const 6))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $finish_entity (i32.const 0x464f00) (i32.const 23) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/peer ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465000) (i32.const 11))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x465040) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465080) (i32.const 14))
    (call $w_text (i32.const 0x4650c0) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465100) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $finish_entity (i32.const 0x464fc0) (i32.const 23) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/peer-id ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465080) (i32.const 14))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x465140) (i32.const 26) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/connect/authenticate ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x4651c0) (i32.const 36))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x465200) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $w_text (i32.const 0x465040) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465080) (i32.const 14))
    (call $w_text (i32.const 0x4650c0) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465100) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $finish_entity (i32.const 0x465180) (i32.const 48) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/connect/hello ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465280) (i32.const 29))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 8))
    (call $w_text (i32.const 0x465200) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $w_text (i32.const 0x465040) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465080) (i32.const 14))
    (call $w_text (i32.const 0x4652c0) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x465300) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465340) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465380) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4653c0) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x465400) (i32.const 12))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x465240) (i32.const 41) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/envelope ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465480) (i32.const 24))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x463280) (i32.const 13))
    (call $finish_entity (i32.const 0x465440) (i32.const 36) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/error ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465500) (i32.const 21))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x465540) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465580) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x4655c0) (i32.const 15))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $finish_entity (i32.const 0x4654c0) (i32.const 33) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/execute ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465640) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 11))
    (call $w_text (i32.const 0x4647c0) (i32.const 3))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x465680) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x4656c0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463780) (i32.const 13))
    (call $w_text (i32.const 0x465700) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x465740) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465780) (i32.const 31))
    (call $w_text (i32.const 0x464800) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x4657c0) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x465800) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464780) (i32.const 20))
    (call $w_text (i32.const 0x465840) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465880) (i32.const 13))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x4658c0) (i32.const 18))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465900) (i32.const 25))
    (call $finish_entity (i32.const 0x465600) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/execute/response ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465980) (i32.const 32))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x4659c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x465a00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465a40) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x465a80) (i32.const 24))
    (call $w_text (i32.const 0x465840) (i32.const 10))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x465940) (i32.const 44) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/protocol/resource-target ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465780) (i32.const 31))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x463f80) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x465b00) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $finish_entity (i32.const 0x465ac0) (i32.const 43) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/resource-limits ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464640) (i32.const 22))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x465b80) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465bc0) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465c00) (i32.const 18))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $finish_entity (i32.const 0x465b40) (i32.const 34) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/signature ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465c80) (i32.const 16))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x465cc0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x465d00) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x465d40) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465d80) (i32.const 9))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x4634c0) (i32.const 15))
    (call $finish_entity (i32.const 0x465c40) (i32.const 28) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/tree/get-request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465e00) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x465e40) (i32.const 4))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x465e80) (i32.const 5))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465ec0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465f00) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x465dc0) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/tree/listing ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x465f80) (i32.const 19))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 5))
    (call $w_text (i32.const 0x465fc0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x466000) (i32.const 5))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x465ec0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x466040) (i32.const 7))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x466080) (i32.const 25))
    (call $w_text (i32.const 0x4660c0) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $finish_entity (i32.const 0x465f40) (i32.const 31) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/tree/listing-entry ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x466080) (i32.const 25))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466140) (i32.const 4))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $w_text (i32.const 0x466180) (i32.const 12))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463440) (i32.const 14))
    (call $finish_entity (i32.const 0x466100) (i32.const 37) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/tree/path ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463880) (i32.const 16))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x4661c0) (i32.const 28) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/tree/put-request ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x466240) (i32.const 23))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x463380) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x465f00) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466280) (i32.const 13))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463200) (i32.const 11))
    (call $finish_entity (i32.const 0x466200) (i32.const 35) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/type ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x463000) (i32.const 11))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x464ac0) (i32.const 4))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x466340) (i32.const 22))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x466380) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4663c0) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466400) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x466440) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x4662c0) (i32.const 23) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/type/field-spec ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x466340) (i32.const 22))
    (call $w_text (i32.const 0x466300) (i32.const 6))
    (call $w_map (i64.const 11))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x466340) (i32.const 22))
    (call $w_text (i32.const 0x466500) (i32.const 7))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463100) (i32.const 13))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x466340) (i32.const 22))
    (call $w_text (i32.const 0x4650c0) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463440) (i32.const 14))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466600) (i32.const 8))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x466340) (i32.const 22))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x466640) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463700) (i32.const 14))
    (call $w_text (i32.const 0x466400) (i32.const 9))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4664c0) (i32.const 6))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x466680) (i32.const 10))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $w_text (i32.const 0x463f00) (i32.const 11))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466540) (i32.const 8))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4665c0) (i32.const 8))
    (call $w_text (i32.const 0x463080) (i32.const 11))
    (call $w_text (i32.const 0x466580) (i32.const 8))
    (i32.store8 (global.get $g_wp) (i32.const 0xf5)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))
    (call $finish_entity (i32.const 0x466480) (i32.const 34) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    ;; --- system/type/system/type/name ---
    (global.set $g_wp (i32.const 0xA08000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x464ac0) (i32.const 4)) (call $w_text (i32.const 0x464c80) (i32.const 16))
    (call $w_text (i32.const 0x4663c0) (i32.const 7)) (call $w_text (i32.const 0x463180) (i32.const 16))
    (call $finish_entity (i32.const 0x4666c0) (i32.const 28) (i32.const 0x463000) (i32.const 11) (i32.sub (global.get $g_wp) (i32.const 0xA08000)))
    )

  ;; find entity in the `included` map at $inclp whose 33-byte key == $key; ptr or 0.
  (func $included_find_by_key (param $inclp i32) (param $key i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $kb i32) (local $kl i32) (local $valp i32)
    (local.set $p (call $rd_head (local.get $inclp)))
    (if (i32.ne (global.get $g_major) (i32.const 5)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $kb (call $rd_head (local.get $p)))
      (local.set $kl (i32.wrap_i64 (global.get $g_arg)))
      (local.set $valp (i32.add (local.get $kb) (local.get $kl)))
      (if (i32.eq (local.get $kl) (i32.const 33))
        (then (if (call $streq (local.get $kb) (i32.const 33) (local.get $key) (i32.const 33))
          (then (return (local.get $valp))))))
      (local.set $p (call $skip (local.get $valp)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  ;; find a system/signature in `included` with data.signer==$signer ∧ data.target==$target;
  ;; return its 64-byte signature ptr, or 0.
  (func $find_req_sig (param $inclp i32) (param $signer i32) (param $target i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $kb i32) (local $kl i32) (local $valp i32)
    (local $t i32) (local $sd i32) (local $v i32) (local $vp i32)
    (local.set $p (call $rd_head (local.get $inclp)))
    (if (i32.ne (global.get $g_major) (i32.const 5)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $kb (call $rd_head (local.get $p)))
      (local.set $kl (i32.wrap_i64 (global.get $g_arg)))
      (local.set $valp (i32.add (local.get $kb) (local.get $kl)))
      (block $next
        (local.set $t (call $map_find (local.get $valp) (i32.const 0x460020) (i32.const 4)))          ;; type
        (br_if $next (i32.eq (local.get $t) (i32.const -1)))
        (local.set $vp (call $rd_head (local.get $t)))
        (br_if $next (i32.eqz (call $streq (local.get $vp) (i32.wrap_i64 (global.get $g_arg)) (i32.const 0x461500) (i32.const 16))))  ;; system/signature
        (local.set $sd (call $map_find (local.get $valp) (i32.const 0x460010) (i32.const 4)))          ;; data
        (br_if $next (i32.eq (local.get $sd) (i32.const -1)))
        (local.set $v (call $map_find (local.get $sd) (i32.const 0x461100) (i32.const 6)))             ;; signer
        (br_if $next (i32.eq (local.get $v) (i32.const -1)))
        (local.set $vp (call $rd_head (local.get $v)))
        (br_if $next (i32.eqz (call $streq (local.get $vp) (i32.const 33) (local.get $signer) (i32.const 33))))
        (local.set $v (call $map_find (local.get $sd) (i32.const 0x461140) (i32.const 6)))             ;; target
        (br_if $next (i32.eq (local.get $v) (i32.const -1)))
        (local.set $vp (call $rd_head (local.get $v)))
        (br_if $next (i32.eqz (call $streq (local.get $vp) (i32.const 33) (local.get $target) (i32.const 33))))
        (local.set $v (call $map_find (local.get $sd) (i32.const 0x4610c0) (i32.const 9)))             ;; signature
        (br_if $next (i32.eq (local.get $v) (i32.const -1)))
        (return (call $rd_head (local.get $v))))
      (local.set $p (call $skip (local.get $valp)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  (func $array_contains_star (param $arr i32) (param $needle i32) (param $nlen i32) (result i32)
    (if (call $array_contains (local.get $arr) (local.get $needle) (local.get $nlen)) (then (return (i32.const 1))))
    (call $array_contains (local.get $arr) (i32.const 0x4623c0) (i32.const 1)))   ;; "*"

  ;; match $target against a pattern-include array: bare "*", trailing "/*" prefix, or exact.
  (func $resource_matches (param $arr i32) (param $target i32) (param $tlen i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $pp i32) (local $plen i32) (local $pfx i32)
    (local.set $p (call $rd_head (local.get $arr)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $pp (call $rd_head (local.get $p)))
      (local.set $plen (i32.wrap_i64 (global.get $g_arg)))
      (local.set $p (i32.add (local.get $pp) (local.get $plen)))
      (block $nomatch
        (if (i32.and (i32.eq (local.get $plen) (i32.const 1)) (i32.eq (i32.load8_u (local.get $pp)) (i32.const 0x2a)))
          (then (return (i32.const 1))))                                              ;; bare "*"
        (if (i32.ge_u (local.get $plen) (i32.const 2))
          (then (if (i32.and (i32.eq (i32.load8_u (i32.add (local.get $pp) (i32.sub (local.get $plen) (i32.const 1)))) (i32.const 0x2a))
                             (i32.eq (i32.load8_u (i32.add (local.get $pp) (i32.sub (local.get $plen) (i32.const 2)))) (i32.const 0x2f)))
            (then                                                                     ;; trailing "/*"
              (local.set $pfx (i32.sub (local.get $plen) (i32.const 1)))
              (br_if $nomatch (i32.lt_u (local.get $tlen) (local.get $pfx)))
              (if (call $streq (local.get $pp) (local.get $pfx) (local.get $target) (local.get $pfx))
                (then (return (i32.const 1))))
              (br $nomatch)))))
        (if (call $streq (local.get $pp) (local.get $plen) (local.get $target) (local.get $tlen))
          (then (return (i32.const 1)))))                                             ;; exact
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  ;; base58 (Bitcoin alphabet, excludes 0/O/I/l) membership — for $is_peer_id_seg.
  (func $b58_char (param $c i32) (result i32)
    (if (i32.and (i32.ge_u (local.get $c) (i32.const 0x31)) (i32.le_u (local.get $c) (i32.const 0x39)))
      (then (return (i32.const 1))))                                              ;; '1'-'9'
    (if (i32.and (i32.ge_u (local.get $c) (i32.const 0x41)) (i32.le_u (local.get $c) (i32.const 0x5a)))
      (then (if (i32.and (i32.ne (local.get $c) (i32.const 0x49)) (i32.ne (local.get $c) (i32.const 0x4f)))
              (then (return (i32.const 1))))))                                    ;; 'A'-'Z' minus I,O
    (if (i32.and (i32.ge_u (local.get $c) (i32.const 0x61)) (i32.le_u (local.get $c) (i32.const 0x7a)))
      (then (if (i32.ne (local.get $c) (i32.const 0x6c)) (then (return (i32.const 1))))))  ;; 'a'-'z' minus l
    (i32.const 0))

  ;; §5.2 extract_peer helper: is $seg (ptr,len) shaped like a peer id (>=46-char base58)?
  ;; Byte-exact parity with the rust/python reference `is_peer_id` (rust/src/peer/capability.rs).
  ;; wasm-wat's own $path_valid already uses a coarser >=32 threshold for the unrelated
  ;; absolute-path-vs-bare-word question; kept separate here since this feeds check_permission.
  (func $is_peer_id_seg (export "is_peer_id_seg") (param $p i32) (param $len i32) (result i32)
    (local $i i32)
    (if (i32.lt_u (local.get $len) (i32.const 46)) (then (return (i32.const 0))))
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (if (i32.eqz (call $b58_char (i32.load8_u (i32.add (local.get $p) (local.get $i)))))
        (then (return (i32.const 0))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 1))

  ;; §5.2 peers-scope (id-scope: bare "*" / trailing "/*" / exact literal — no path
  ;; canonicalization, §5.4/F40 — reuses $resource_matches, the same literal matcher already
  ;; used for the resources path-scope dimension since wasm-wat applies no frame translation).
  ;; A grant with no "peers" key defaults to {include:[local_peer_id]} (no exclude) — §5.2 spec
  ;; text line 1040/2378. $g is the current grant entry, matching $grant_scope_ok's convention.
  (func $peers_scope_ok (export "peers_scope_ok") (param $g i32) (param $target i32) (param $tlen i32) (result i32)
    (local $m i32) (local $inc i32) (local $exc i32)
    (local.set $m (call $map_find (local.get $g) (i32.const 0x461980) (i32.const 5)))   ;; peers
    (if (i32.eq (local.get $m) (i32.const -1))
      (then (return (call $streq (local.get $target) (local.get $tlen) (i32.const 0x420200) (i32.load (i32.const 0x4202F0))))))
    (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))   ;; include
    (if (i32.eq (local.get $inc) (i32.const -1)) (then (return (i32.const 0))))
    (if (i32.eqz (call $resource_matches (local.get $inc) (local.get $target) (local.get $tlen))) (then (return (i32.const 0))))
    (local.set $exc (call $map_find (local.get $m) (i32.const 0x4619c0) (i32.const 7)))   ;; exclude
    (if (i32.ne (local.get $exc) (i32.const -1))
      (then (if (call $resource_matches (local.get $exc) (local.get $target) (local.get $tlen)) (then (return (i32.const 0))))))
    (i32.const 1))

  ;; ∃ grant permitting op×handler(g_hptr/len)×target×peer(g_tpp/len) ? "*" honored per dimension.
  ;; §5.5a surface 1 — the DISPATCH boundary. Does some pattern in a grant's resources cover
  ;; the request's target path?
  ;;
  ;; The two sides canonicalize against DIFFERENT frames, and that asymmetry is the rule:
  ;; a cap's resource patterns are the GRANTER's to write, so they canonicalize against the
  ;; granter's peer_id; the request target is a path into THIS peer's namespace, so it
  ;; canonicalizes against the local peer_id. Frame both against the local peer and a
  ;; foreign-granted bare "*" silently becomes "/{verifier}/*" and authorizes the verifier's
  ;; own namespace — which is the whole point of §5.5a and the defect
  ;; captok_form_dispatch_minted_pl_presented_xpeer exists to catch.
  (func $resources_cover_target (param $inc i32) (param $target i32) (param $tlen i32)
                                (param $fr i32) (param $frlen i32) (result i32)
    (local $tclen i32) (local $n i64) (local $i i64) (local $p i32) (local $ep i32) (local $el i32) (local $plen i32)
    (local.set $tclen (call $canon (local.get $target) (local.get $tlen)
                                   (i32.const 0x420200) (i32.load (i32.const 0x4202F0)) (i32.const 0x9A0A00)))
    (local.set $p (call $rd_head (local.get $inc)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $ep (call $rd_head (local.get $p)))
      (local.set $el (i32.wrap_i64 (global.get $g_arg)))
      (local.set $p (i32.add (local.get $ep) (local.get $el)))
      (local.set $plen (call $canon (local.get $ep) (local.get $el) (local.get $fr) (local.get $frlen) (i32.const 0x9A0E00)))
      (if (call $pat_covers (i32.const 0x9A0A00) (local.get $tclen) (i32.const 0x9A0E00) (local.get $plen))
        (then (return (i32.const 1))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  (func $grant_scope_ok (param $td i32) (param $target i32) (param $tlen i32) (param $op i32) (param $oplen i32) (param $fr i32) (param $frlen i32) (result i32)
    (local $grants i32) (local $n i64) (local $i i64) (local $g i32) (local $m i32) (local $inc i32)
    (local.set $grants (call $map_find (local.get $td) (i32.const 0x4611c0) (i32.const 6)))   ;; grants
    (if (i32.eq (local.get $grants) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $g (call $rd_head (local.get $grants)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (block $next
        (local.set $m (call $map_find (local.get $g) (i32.const 0x461380) (i32.const 10)))   ;; operations
        (br_if $next (i32.eq (local.get $m) (i32.const -1)))
        (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))   ;; include
        (br_if $next (i32.eq (local.get $inc) (i32.const -1)))
        (br_if $next (i32.eqz (call $array_contains_star (local.get $inc) (local.get $op) (local.get $oplen))))
        (local.set $m (call $map_find (local.get $g) (i32.const 0x461300) (i32.const 8)))     ;; handlers
        (br_if $next (i32.eq (local.get $m) (i32.const -1)))
        (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))
        (br_if $next (i32.eq (local.get $inc) (i32.const -1)))
        (br_if $next (i32.eqz (call $array_contains_star (local.get $inc) (global.get $g_hptr) (global.get $g_hlen))))
        (br_if $next (i32.eqz (call $peers_scope_ok (local.get $g) (global.get $g_tpp) (global.get $g_tplen))))
        (local.set $m (call $map_find (local.get $g) (i32.const 0x461340) (i32.const 9)))     ;; resources
        (br_if $next (i32.eq (local.get $m) (i32.const -1)))
        (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))
        (br_if $next (i32.eq (local.get $inc) (i32.const -1)))
        (if (call $resources_cover_target (local.get $inc) (local.get $target) (local.get $tlen)
                                          (local.get $fr) (local.get $frlen))
          (then (return (i32.const 1)))))
      (local.set $g (call $skip (local.get $g)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  ;; ∃ grant permitting op×handler(g_hptr/len)? (no resource dimension — for ops that carry
  ;; no resource.targets: request/configure/revoke). "*" honored per dimension.
  (func $op_scope_ok (param $td i32) (param $op i32) (param $oplen i32) (result i32)
    (local $grants i32) (local $n i64) (local $i i64) (local $g i32) (local $m i32) (local $inc i32)
    (local.set $grants (call $map_find (local.get $td) (i32.const 0x4611c0) (i32.const 6)))   ;; grants
    (if (i32.eq (local.get $grants) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $g (call $rd_head (local.get $grants)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (block $next
        (local.set $m (call $map_find (local.get $g) (i32.const 0x461380) (i32.const 10)))   ;; operations
        (br_if $next (i32.eq (local.get $m) (i32.const -1)))
        (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))   ;; include
        (br_if $next (i32.eq (local.get $inc) (i32.const -1)))
        (br_if $next (i32.eqz (call $array_contains_star (local.get $inc) (local.get $op) (local.get $oplen))))
        (local.set $m (call $map_find (local.get $g) (i32.const 0x461300) (i32.const 8)))     ;; handlers
        (br_if $next (i32.eq (local.get $m) (i32.const -1)))
        (local.set $inc (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))
        (br_if $next (i32.eq (local.get $inc) (i32.const -1)))
        (br_if $next (i32.eqz (call $array_contains_star (local.get $inc) (global.get $g_hptr) (global.get $g_hlen))))
        (if (call $peers_scope_ok (local.get $g) (global.get $g_tpp) (global.get $g_tplen))
          (then (return (i32.const 1)))))
      (local.set $g (call $skip (local.get $g)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 0))

  ;; §5.2 operation-scope gate for a capability op with no resource.targets (request/configure/
  ;; revoke): the presented token must be temporally valid and carry a grant covering op×handler.
  ;; The resource dimension is skipped (there is no target), mirroring the reference peer's
  ;; FindMatchingGrant. A floor cap (capability:request only) 403s configure/revoke here.
  (func $verify_op_scope (param $edp i32) (param $in i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $cap i32) (local $capp i32) (local $incl i32) (local $tok i32) (local $td i32)
    (local $op i32) (local $opp i32) (local $oplen i32) (local $f i32) (local $ms i64)
    (call $derive_handler (local.get $edp))
    (local.set $cap (call $map_find (local.get $edp) (i32.const 0x462040) (i32.const 10)))
    (if (i32.eq (local.get $cap) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $capp (call $rd_head (local.get $cap)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tok (call $included_find_by_key (local.get $incl) (local.get $capp)))
    (if (i32.eqz (local.get $tok)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $td (call $map_find (local.get $tok) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $td) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x462180) (i32.const 10)))          ;; expires_at
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i64.gt_u (local.get $ms) (global.get $g_arg)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x4621c0) (i32.const 10)))          ;; not_before
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i64.lt_u (local.get $ms) (global.get $g_arg)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
    (local.set $op (call $map_find (local.get $edp) (i32.const 0x4600c0) (i32.const 9)))         ;; operation
    (if (i32.eq (local.get $op) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $opp (call $rd_head (local.get $op)))
    (local.set $oplen (i32.wrap_i64 (global.get $g_arg)))
    (if (call $op_scope_ok (local.get $td) (local.get $opp) (local.get $oplen)) (then (return (i32.const 0))))
    (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))

  ;; ================= §6.2 attenuation (request handler) =================
  ;; get_include(scopemap, key) → the scope's `include` array value ptr, or 0 if absent.
  (func $get_include (param $g i32) (param $key i32) (param $klen i32) (result i32)
    (local $m i32)
    (local.set $m (call $map_find (local.get $g) (local.get $key) (local.get $klen)))
    (if (i32.eq (local.get $m) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $m (call $map_find (local.get $m) (i32.const 0x4613c0) (i32.const 7)))   ;; include
    (if (i32.eq (local.get $m) (i32.const -1)) (then (return (i32.const 0))))
    (local.get $m))

  ;; every element of $sub ⊆ $super (star-aware: a "*" in super covers any element).
  (func $array_subset_star (param $sub i32) (param $super i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $ep i32) (local $el i32)
    (local.set $p (call $rd_head (local.get $sub)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $ep (call $rd_head (local.get $p)))
      (local.set $el (i32.wrap_i64 (global.get $g_arg)))
      (local.set $p (i32.add (local.get $ep) (local.get $el)))
      (if (i32.eqz (call $array_contains_star (local.get $super) (local.get $ep) (local.get $el)))
        (then (return (i32.const 0))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 1))

  ;; every element of $sub is matched by some pattern in $super (bare */trailing /*/exact).
  (func $resources_subset (param $sub i32) (param $super i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $ep i32) (local $el i32)
    (local.set $p (call $rd_head (local.get $sub)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $ep (call $rd_head (local.get $p)))
      (local.set $el (i32.wrap_i64 (global.get $g_arg)))
      (local.set $p (i32.add (local.get $ep) (local.get $el)))
      (if (i32.eqz (call $resource_matches (local.get $super) (local.get $ep) (local.get $el)))
        (then (return (i32.const 0))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 1))

  ;; a caller grant covers a requested grant iff req.operations ⊆ caller.operations,
  ;; req.handlers ⊆ caller.handlers, and req.resources are all matched by caller.resources.
  (func $grant_covers (param $caller i32) (param $req i32) (result i32)
    (local $rs i32) (local $cs i32)
    (local.set $rs (call $get_include (local.get $req) (i32.const 0x461380) (i32.const 10)))     ;; operations
    (if (i32.eqz (local.get $rs)) (then (return (i32.const 0))))
    (local.set $cs (call $get_include (local.get $caller) (i32.const 0x461380) (i32.const 10)))
    (if (i32.eqz (local.get $cs)) (then (return (i32.const 0))))
    (if (i32.eqz (call $array_subset_star (local.get $rs) (local.get $cs))) (then (return (i32.const 0))))
    (local.set $rs (call $get_include (local.get $req) (i32.const 0x461300) (i32.const 8)))       ;; handlers
    (if (i32.eqz (local.get $rs)) (then (return (i32.const 0))))
    (local.set $cs (call $get_include (local.get $caller) (i32.const 0x461300) (i32.const 8)))
    (if (i32.eqz (local.get $cs)) (then (return (i32.const 0))))
    (if (i32.eqz (call $array_subset_star (local.get $rs) (local.get $cs))) (then (return (i32.const 0))))
    (local.set $rs (call $get_include (local.get $req) (i32.const 0x461340) (i32.const 9)))       ;; resources
    (if (i32.eqz (local.get $rs)) (then (return (i32.const 1))))                                  ;; none requested → ok
    (local.set $cs (call $get_include (local.get $caller) (i32.const 0x461340) (i32.const 9)))
    (if (i32.eqz (local.get $cs)) (then (return (i32.const 0))))
    (call $resources_subset (local.get $rs) (local.get $cs)))

  ;; §6.2: every requested grant must be covered by some grant in the caller's token; the
  ;; request must not widen scope beyond the caller's authority. Empty request → attenuated.
  (func $grants_attenuated (param $reqg i32) (param $ctd i32) (result i32)
    (local $rn i64) (local $ri i64) (local $rp i32) (local $rgrant i32)
    (local $cg i32) (local $cn i64) (local $ci i64) (local $cp i32) (local $covered i32)
    (local.set $rp (call $rd_head (local.get $reqg)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $rn (global.get $g_arg))
    (block $rdone (loop $rL
      (br_if $rdone (i64.ge_u (local.get $ri) (local.get $rn)))
      (local.set $rgrant (local.get $rp))
      (local.set $cg (call $map_find (local.get $ctd) (i32.const 0x4611c0) (i32.const 6)))        ;; caller grants
      (if (i32.eq (local.get $cg) (i32.const -1)) (then (return (i32.const 0))))
      (local.set $cp (call $rd_head (local.get $cg)))
      (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
      (local.set $cn (global.get $g_arg))
      (local.set $covered (i32.const 0))
      (local.set $ci (i64.const 0))
      (block $cdone (loop $cL
        (br_if $cdone (i64.ge_u (local.get $ci) (local.get $cn)))
        (if (call $grant_covers (local.get $cp) (local.get $rgrant))
          (then (local.set $covered (i32.const 1)) (br $cdone)))
        (local.set $cp (call $skip (local.get $cp)))
        (local.set $ci (i64.add (local.get $ci) (i64.const 1)))
        (br $cL)))
      (if (i32.eqz (local.get $covered)) (then (return (i32.const 0))))
      (local.set $rp (call $skip (local.get $rgrant)))
      (local.set $ri (i64.add (local.get $ri) (i64.const 1)))
      (br $rL)))
    (i32.const 1))

  ;; parse data.uri (entity://<peer>/<handler>) → g_hptr/g_hlen (handler, default system/tree)
  ;; and g_tpp/g_tplen (§5.2 extract_peer target_peer: the uri's first path segment when it is
  ;; peer-id-shaped, else local_peer_id — line 2196 of the spec). Defaults are set up front so
  ;; every early-return (missing/malformed/short uri) still leaves target_peer = local_peer_id,
  ;; matching extract_peer's else-branch.
  (func $derive_handler (param $edp i32)
    (local $u i32) (local $up i32) (local $ulen i32) (local $cur i32) (local $end i32) (local $segp i32) (local $seglen i32)
    (global.set $g_hptr (i32.const 0x461640))   ;; system/tree
    (global.set $g_hlen (i32.const 11))
    (global.set $g_tpp (i32.const 0x420200))    ;; default target_peer = local_peer_id
    (global.set $g_tplen (i32.load (i32.const 0x4202F0)))
    (local.set $u (call $map_find (local.get $edp) (i32.const 0x462100) (i32.const 3)))   ;; uri
    (if (i32.eq (local.get $u) (i32.const -1)) (then (return)))
    (local.set $up (call $rd_head (local.get $u)))
    (local.set $ulen (i32.wrap_i64 (global.get $g_arg)))
    (if (i32.lt_u (local.get $ulen) (i32.const 9)) (then (return)))
    (if (i32.eqz (call $streq (local.get $up) (i32.const 9) (i32.const 0x462380) (i32.const 9))) (then (return)))  ;; "entity://"
    (local.set $cur (i32.add (local.get $up) (i32.const 9)))
    (local.set $end (i32.add (local.get $up) (local.get $ulen)))
    (local.set $segp (local.get $cur))
    (block $f (loop $L
      (br_if $f (i32.ge_u (local.get $cur) (local.get $end)))
      (br_if $f (i32.eq (i32.load8_u (local.get $cur)) (i32.const 0x2f)))
      (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
      (br $L)))
    (local.set $seglen (i32.sub (local.get $cur) (local.get $segp)))
    (if (call $is_peer_id_seg (local.get $segp) (local.get $seglen))
      (then
        (global.set $g_tpp (local.get $segp))
        (global.set $g_tplen (local.get $seglen))))
    (if (i32.lt_u (i32.add (local.get $cur) (i32.const 1)) (local.get $end))
      (then
        (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
        (global.set $g_hptr (local.get $cur))
        (global.set $g_hlen (i32.sub (local.get $end) (local.get $cur))))))

  (func $seg_ok (param $p i32) (param $len i32) (result i32)
    (if (i32.and (i32.eq (local.get $len) (i32.const 1)) (i32.eq (i32.load8_u (local.get $p)) (i32.const 0x2e))) (then (return (i32.const 0))))
    (if (i32.and (i32.eq (local.get $len) (i32.const 2))
                 (i32.and (i32.eq (i32.load8_u (local.get $p)) (i32.const 0x2e)) (i32.eq (i32.load8_u (i32.add (local.get $p) (i32.const 1))) (i32.const 0x2e))))
      (then (return (i32.const 0))))
    (i32.const 1))

  ;; §"invalid_path": reject NUL, internal empty segment, or a "."/".." segment. Trailing '/' OK.
  (func $path_valid (param $t i32) (param $tlen i32) (result i32)
    (local $i i32) (local $ss i32) (local $c i32) (local $sl i32) (local $s1 i32)
    ;; §1.4: a leading '/' marks an absolute '/{peer_id}/...' path. It is valid ONLY if the first
    ;; segment is a peer-id (not a bare word): caller paths are otherwise peer-relative, so a
    ;; leading '/' followed by e.g. "system" is malformed (CORE-TREE-PATH-FLEX-1 reject_leading_slash).
    ;; Peer-ids are ~44-46-char base58; a real segment name is short — a >=32 length gate separates
    ;; them without a full base58 decode. Skip the root slash so its empty segment isn't rejected.
    (if (i32.and (i32.gt_u (local.get $tlen) (i32.const 0)) (i32.eq (i32.load8_u (local.get $t)) (i32.const 0x2f)))
      (then
        (local.set $s1 (i32.const 1))
        (block $f (loop $fl
          (br_if $f (i32.ge_u (local.get $s1) (local.get $tlen)))
          (br_if $f (i32.eq (i32.load8_u (i32.add (local.get $t) (local.get $s1))) (i32.const 0x2f)))
          (local.set $s1 (i32.add (local.get $s1) (i32.const 1))) (br $fl)))
        (if (i32.lt_u (i32.sub (local.get $s1) (i32.const 1)) (i32.const 32)) (then (return (i32.const 0))))  ;; first seg not a peer-id
        (local.set $i (i32.const 1)) (local.set $ss (i32.const 1))))
    (block $done (loop $L
      (if (i32.eq (local.get $i) (local.get $tlen))
        (then
          (local.set $sl (i32.sub (local.get $i) (local.get $ss)))
          (if (local.get $sl) (then (if (i32.eqz (call $seg_ok (i32.add (local.get $t) (local.get $ss)) (local.get $sl))) (then (return (i32.const 0))))))
          (return (i32.const 1))))
      (local.set $c (i32.load8_u (i32.add (local.get $t) (local.get $i))))
      (if (i32.eqz (local.get $c)) (then (return (i32.const 0))))
      (if (i32.eq (local.get $c) (i32.const 0x2f))
        (then
          (local.set $sl (i32.sub (local.get $i) (local.get $ss)))
          (if (i32.eqz (local.get $sl)) (then (return (i32.const 0))))
          (if (i32.eqz (call $seg_ok (i32.add (local.get $t) (local.get $ss)) (local.get $sl))) (then (return (i32.const 0))))
          (local.set $ss (i32.add (local.get $i) (i32.const 1)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 1))

  ;; §4.10(b) chain-depth: walk capability→included token→parent…; >64 → 400 chain_depth_exceeded.
  (func $chain_depth_check (param $edp i32) (param $in i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $cap i32) (local $cur i32) (local $incl i32) (local $depth i32) (local $ent i32) (local $d i32) (local $par i32)
    (local.set $cap (call $map_find (local.get $edp) (i32.const 0x462040) (i32.const 10)))   ;; capability
    (if (i32.eq (local.get $cap) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $cur (call $rd_head (local.get $cap)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))    ;; included
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (i32.const 0))))
    (block $done (loop $L
      (local.set $ent (call $included_find_by_key (local.get $incl) (local.get $cur)))
      (br_if $done (i32.eqz (local.get $ent)))
      (local.set $d (call $map_find (local.get $ent) (i32.const 0x460010) (i32.const 4)))
      (br_if $done (i32.eq (local.get $d) (i32.const -1)))
      (local.set $par (call $map_find (local.get $d) (i32.const 0x462140) (i32.const 6)))    ;; parent
      (br_if $done (i32.eq (local.get $par) (i32.const -1)))
      (local.set $cur (call $rd_head (local.get $par)))
      (local.set $depth (i32.add (local.get $depth) (i32.const 1)))
      (if (i32.gt_u (local.get $depth) (i32.const 64))
        (then (return (call $build_error (local.get $out) (i32.const 0x462280) (i32.const 20) (i32.const 400) (local.get $rid) (local.get $rlen)))))
      (br $L)))
    (i32.const 0))

  ;; §5.2 auth-class (401): author present + signed the root content_hash.
  (func $verify_auth (param $edp i32) (param $in i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $author i32) (local $ap i32) (local $incl i32) (local $peer i32) (local $pd i32) (local $pk i32) (local $pkp i32)
    (local $root i32) (local $rc i32) (local $rcp i32) (local $sig i32)
    (local.set $author (call $map_find (local.get $edp) (i32.const 0x462000) (i32.const 6)))     ;; author
    (if (i32.eq (local.get $author) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ap (call $rd_head (local.get $author)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $peer (call $included_find_by_key (local.get $incl) (local.get $ap)))
    (if (i32.eqz (local.get $peer)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pd (call $map_find (local.get $peer) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pd) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pk (call $map_find (local.get $pd) (i32.const 0x461080) (i32.const 10)))         ;; public_key
    (if (i32.eq (local.get $pk) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pkp (call $rd_head (local.get $pk)))
    (local.set $root (call $map_find (local.get $in) (i32.const 0x460000) (i32.const 4)))        ;; root
    (if (i32.eq (local.get $root) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $rc (call $map_find (local.get $root) (i32.const 0x460030) (i32.const 12)))       ;; content_hash
    (if (i32.eq (local.get $rc) (i32.const -1)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $rcp (call $rd_head (local.get $rc)))
    (local.set $sig (call $find_req_sig (local.get $incl) (local.get $ap) (local.get $rcp)))
    (if (i32.eqz (local.get $sig)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (if (call $ed_verify (local.get $pkp) (local.get $rcp) (i32.const 33) (local.get $sig)) (then (return (call $err_authfail (local.get $out) (local.get $rid) (local.get $rlen)))))
    (i32.const 0))

  ;; ==================== §5.5 delegation-chain verification ====================
  ;; Until 2026-08-29 this peer had NO chain walk: $verify_cap required a presented
  ;; capability's granter to be this peer and refused everything else, under the reading
  ;; that a fail-closed root-trust gate is a safe placeholder. It is not a safe placeholder,
  ;; it is a silent one — every chain vector in the oracle's `security` category is
  ;; reject-direction, so a peer that refuses all chains answers about ten of them correctly
  ;; for a reason unrelated to what they test, and CAP-5/CAP-6/CAP-6a (which present a
  ;; DELEGATED capability) were refused two gates before the mint they are named after.
  ;;
  ;; Scratch, 0x9A0000..0x9A1000 — between the pending-reentry table (0x990000, 2 KiB) and
  ;; the store arena (0xA10000):
  ;;   0x9A0000 child-link granter peer_id (128 cap)   0x9A0080 its length
  ;;   0x9A0100 parent-link granter peer_id (128 cap)  0x9A0180 its length
  ;;   0x9A0200 canonicalized child pattern (1 KiB)
  ;;   0x9A0600 canonicalized parent pattern (1 KiB)
  ;;   0x9A0800 the child link's granter hash, carried across one hop (33)
  ;;   0x9A0A00 canonicalized dispatch target (1 KiB)
  ;;   0x9A0E00 canonicalized dispatch pattern (1 KiB)
  ;;   0x9A1200 dispatch-surface granter frame (128) + 0x9A1280 its length

  ;; peer_id_of(incl, hash33, out, out_len_ptr) → 1 on success.
  ;; The §5.5a canonicalization FRAME for a link is its granter's peer_id — which is not on
  ;; the wire. It is derived from the granter's system/peer entity in `included`, the same
  ;; entity the link's signature is verified against.
  (func $peerid_of (param $incl i32) (param $h i32) (param $out i32) (param $lenp i32) (result i32)
    (local $e i32) (local $d i32) (local $pk i32) (local $pkp i32)
    (local.set $e (call $included_find_by_key (local.get $incl) (local.get $h)))
    (if (i32.eqz (local.get $e)) (then (return (i32.const 0))))
    (local.set $d (call $map_find (local.get $e) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $d) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $pk (call $map_find (local.get $d) (i32.const 0x461080) (i32.const 10)))
    (if (i32.eq (local.get $pk) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $pkp (call $rd_head (local.get $pk)))
    (if (i64.ne (global.get $g_arg) (i64.const 32)) (then (return (i32.const 0))))
    (if (call $format_peer_id (local.get $pkp) (local.get $out) (i32.const 128) (local.get $lenp))
      (then (return (i32.const 0))))
    (i32.const 1))

  ;; §5.5a canonicalize(pattern, frame_peer_id) → out; returns the canonical length.
  ;;   leading "/"  ⇒ absolute: the pattern names a peer position explicitly — copy verbatim
  ;;   otherwise    ⇒ peer-relative: "/" + frame + "/" + pattern
  ;; Bare "*" needs NO special case and deliberately does not get one: it falls out of the
  ;; general rule as "/{frame}/*", which is exactly what §5.5a says it means — "the granter's
  ;; own namespace, NOT a universal cross-peer wildcard". Special-casing it is how the
  ;; no-canon-before-wildcard-shortcircuit bug shape (§5.5a's informative footnote) gets built.
  (func $canon (param $p i32) (param $plen i32) (param $fr i32) (param $frlen i32) (param $out i32) (result i32)
    (if (i32.and (i32.gt_u (local.get $plen) (i32.const 0))
                 (i32.eq (i32.load8_u (local.get $p)) (i32.const 0x2f)))
      (then (memory.copy (local.get $out) (local.get $p) (local.get $plen))
            (return (local.get $plen))))
    (i32.store8 (local.get $out) (i32.const 0x2f))
    (memory.copy (i32.add (local.get $out) (i32.const 1)) (local.get $fr) (local.get $frlen))
    (i32.store8 (i32.add (local.get $out) (i32.add (local.get $frlen) (i32.const 1))) (i32.const 0x2f))
    (memory.copy (i32.add (local.get $out) (i32.add (local.get $frlen) (i32.const 2)))
                 (local.get $p) (local.get $plen))
    (i32.add (i32.add (local.get $frlen) (i32.const 2)) (local.get $plen)))

  ;; Does parent pattern PP cover child pattern CP? Both canonical, both absolute. Segment-wise:
  ;;   parent "*" as the LAST segment → covers everything remaining
  ;;   parent "*" mid-pattern         → covers exactly one child segment, whatever it is
  ;;   parent literal                 → the child segment must be that literal; a child "*"
  ;;                                    here is BROADER than the parent and is refused
  ;; Both exhausted together → covered; either alone → not covered.
  (func $pat_covers (param $cp i32) (param $cplen i32) (param $pp i32) (param $pplen i32) (result i32)
    (local $ci i32) (local $pi i32) (local $cs i32) (local $cl i32) (local $ps i32) (local $pl i32)
    (if (i32.eqz (local.get $cplen)) (then (return (i32.const 0))))
    (if (i32.eqz (local.get $pplen)) (then (return (i32.const 0))))
    (if (i32.ne (i32.load8_u (local.get $cp)) (i32.const 0x2f)) (then (return (i32.const 0))))
    (if (i32.ne (i32.load8_u (local.get $pp)) (i32.const 0x2f)) (then (return (i32.const 0))))
    (local.set $ci (i32.const 1))
    (local.set $pi (i32.const 1))
    (block $done (loop $L
      (if (i32.ge_u (local.get $pi) (local.get $pplen))
        (then (return (i32.ge_u (local.get $ci) (local.get $cplen)))))
      ;; parent segment — read BEFORE testing whether the child is exhausted, because a
      ;; trailing "*" covers the remainder INCLUDING the empty one. "/{peer}/*" authorizes
      ;; the peer's namespace, and listing that namespace's own root ("/{peer}/") is inside
      ;; it, not above it. Testing child-exhaustion first refuses every root listing, which
      ;; is what this ordering was originally written as and what the two listing checks caught.
      (local.set $ps (i32.add (local.get $pp) (local.get $pi)))
      (local.set $pl (i32.const 0))
      (block $pe (loop $pL
        (br_if $pe (i32.ge_u (i32.add (local.get $pi) (local.get $pl)) (local.get $pplen)))
        (br_if $pe (i32.eq (i32.load8_u (i32.add (local.get $ps) (local.get $pl))) (i32.const 0x2f)))
        (local.set $pl (i32.add (local.get $pl) (i32.const 1)))
        (br $pL)))
      (if (i32.and (i32.and (i32.eq (local.get $pl) (i32.const 1))
                            (i32.eq (i32.load8_u (local.get $ps)) (i32.const 0x2a)))
                   (i32.ge_u (i32.add (local.get $pi) (local.get $pl)) (local.get $pplen)))
        (then (return (i32.const 1))))
      (if (i32.ge_u (local.get $ci) (local.get $cplen)) (then (return (i32.const 0))))
      ;; child segment
      (local.set $cs (i32.add (local.get $cp) (local.get $ci)))
      (local.set $cl (i32.const 0))
      (block $ce (loop $cL
        (br_if $ce (i32.ge_u (i32.add (local.get $ci) (local.get $cl)) (local.get $cplen)))
        (br_if $ce (i32.eq (i32.load8_u (i32.add (local.get $cs) (local.get $cl))) (i32.const 0x2f)))
        (local.set $cl (i32.add (local.get $cl) (i32.const 1)))
        (br $cL)))
      (if (i32.and (i32.eq (local.get $pl) (i32.const 1))
                   (i32.eq (i32.load8_u (local.get $ps)) (i32.const 0x2a)))
        (then)          ;; mid-pattern "*" — matches this one child segment, whatever it is
        (else
          ;; literal parent segment: a "*" child here is broader, and a mismatch is a miss
          (if (i32.and (i32.eq (local.get $cl) (i32.const 1))
                       (i32.eq (i32.load8_u (local.get $cs)) (i32.const 0x2a)))
            (then (return (i32.const 0))))
          (if (i32.eqz (call $streq (local.get $cs) (local.get $cl) (local.get $ps) (local.get $pl)))
            (then (return (i32.const 0))))))
      (local.set $ci (i32.add (i32.add (local.get $ci) (local.get $cl)) (i32.const 1)))
      (local.set $pi (i32.add (i32.add (local.get $pi) (local.get $pl)) (i32.const 1)))
      (br $L)))
    (i32.const 0))

  ;; every element of $sub covered by some element of $super, under §5.5a framing.
  (func $arr_subset_framed (param $sub i32) (param $super i32)
                           (param $sfr i32) (param $sfrlen i32) (param $pfr i32) (param $pfrlen i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $ep i32) (local $el i32) (local $clen i32)
    (local $qn i64) (local $qi i64) (local $q i32) (local $qp i32) (local $ql i32) (local $plen i32) (local $hit i32)
    (local.set $p (call $rd_head (local.get $sub)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $ep (call $rd_head (local.get $p)))
      (local.set $el (i32.wrap_i64 (global.get $g_arg)))
      (local.set $p (i32.add (local.get $ep) (local.get $el)))
      (local.set $clen (call $canon (local.get $ep) (local.get $el) (local.get $sfr) (local.get $sfrlen) (i32.const 0x9A0200)))
      (local.set $hit (i32.const 0))
      (local.set $q (call $rd_head (local.get $super)))
      (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
      (local.set $qn (global.get $g_arg))
      (local.set $qi (i64.const 0))
      (block $qdone (loop $qL
        (br_if $qdone (i64.ge_u (local.get $qi) (local.get $qn)))
        (local.set $qp (call $rd_head (local.get $q)))
        (local.set $ql (i32.wrap_i64 (global.get $g_arg)))
        (local.set $q (i32.add (local.get $qp) (local.get $ql)))
        (local.set $plen (call $canon (local.get $qp) (local.get $ql) (local.get $pfr) (local.get $pfrlen) (i32.const 0x9A0600)))
        (if (call $pat_covers (i32.const 0x9A0200) (local.get $clen) (i32.const 0x9A0600) (local.get $plen))
          (then (local.set $hit (i32.const 1)) (br $qdone)))
        (local.set $qi (i64.add (local.get $qi) (i64.const 1)))
        (br $qL)))
      (if (i32.eqz (local.get $hit)) (then (return (i32.const 0))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 1))

  ;; One scope dimension, child ⊆ parent. $framed selects §5.5a canonicalization, which scopes
  ;; the RESOURCE dimension ONLY — handlers/operations/peers are id-scope and take no frame
  ;; (over-applying the frame is the swift/sql defect: a universal parent grant stops covering
  ;; any child grant the moment the two have different granters, and every delegated cap 403s).
  ;; Both halves of the spec's scope_subset are here: child includes covered by parent includes,
  ;; AND every parent exclude inherited by some child exclude.
  (func $dim_subset (param $cs i32) (param $ps i32) (param $framed i32)
                    (param $cfr i32) (param $cfrlen i32) (param $pfr i32) (param $pfrlen i32) (result i32)
    (local $ci i32) (local $pi i32) (local $cx i32) (local $px i32)
    (local.set $ci (call $map_find (local.get $cs) (i32.const 0x4613c0) (i32.const 7)))
    (local.set $pi (call $map_find (local.get $ps) (i32.const 0x4613c0) (i32.const 7)))
    (if (i32.eq (local.get $ci) (i32.const -1)) (then (return (i32.const 0))))
    (if (i32.eq (local.get $pi) (i32.const -1)) (then (return (i32.const 0))))
    (if (local.get $framed)
      (then (if (i32.eqz (call $arr_subset_framed (local.get $ci) (local.get $pi)
                                                  (local.get $cfr) (local.get $cfrlen)
                                                  (local.get $pfr) (local.get $pfrlen)))
              (then (return (i32.const 0)))))
      (else (if (i32.eqz (call $array_subset_star (local.get $ci) (local.get $pi)))
              (then (return (i32.const 0))))))
    ;; exclude inheritance: each PARENT exclude must be covered by some CHILD exclude —
    ;; the direction is the reverse of includes, because the child must exclude at least as
    ;; much as its parent did. A child that simply drops the parent's exclude widens itself.
    (local.set $px (call $map_find (local.get $ps) (i32.const 0x4619c0) (i32.const 7)))
    (if (i32.eq (local.get $px) (i32.const -1)) (then (return (i32.const 1))))
    (local.set $cx (call $map_find (local.get $cs) (i32.const 0x4619c0) (i32.const 7)))
    (if (i32.eq (local.get $cx) (i32.const -1)) (then (return (i32.const 0))))
    (if (local.get $framed)
      (then (return (call $arr_subset_framed (local.get $px) (local.get $cx)
                                             (local.get $pfr) (local.get $pfrlen)
                                             (local.get $cfr) (local.get $cfrlen)))))
    (call $array_subset_star (local.get $px) (local.get $cx)))

  ;; Constraints: every PARENT key must survive on the child, byte-identical. A dropped key
  ;; widens the child. Allowances: every CHILD key must already exist on the parent,
  ;; byte-identical — an added key widens the child. Opposite directions, same comparison.
  (func $map_attenuated (param $from i32) (param $to i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $kb i32) (local $kl i32)
    (local $vp i32) (local $other i32) (local $vlen i32) (local $olen i32)
    (if (i32.eq (local.get $from) (i32.const -1)) (then (return (i32.const 1))))
    (local.set $p (call $rd_head (local.get $from)))
    (if (i32.ne (global.get $g_major) (i32.const 5)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (if (i64.eqz (local.get $n)) (then (return (i32.const 1))))
    (if (i32.eq (local.get $to) (i32.const -1)) (then (return (i32.const 0))))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $kb (call $rd_head (local.get $p)))
      (local.set $kl (i32.wrap_i64 (global.get $g_arg)))
      (local.set $vp (i32.add (local.get $kb) (local.get $kl)))
      (local.set $other (call $map_find (local.get $to) (local.get $kb) (local.get $kl)))
      (if (i32.eq (local.get $other) (i32.const -1)) (then (return (i32.const 0))))
      (local.set $vlen (i32.sub (call $skip (local.get $vp)) (local.get $vp)))
      (local.set $olen (i32.sub (call $skip (local.get $other)) (local.get $other)))
      (if (i32.eqz (call $streq (local.get $vp) (local.get $vlen) (local.get $other) (local.get $olen)))
        (then (return (i32.const 0))))
      (local.set $p (call $skip (local.get $vp)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const 1))

  ;; All four scope dimensions + constraints + allowances, per §5.6 grant_subset.
  (func $grant_subset_framed (param $cg i32) (param $pg i32)
                             (param $cfr i32) (param $cfrlen i32) (param $pfr i32) (param $pfrlen i32) (result i32)
    (local $a i32) (local $b i32)
    ;; handlers — id-scope, no frame
    (local.set $a (call $map_find (local.get $cg) (i32.const 0x461300) (i32.const 8)))
    (local.set $b (call $map_find (local.get $pg) (i32.const 0x461300) (i32.const 8)))
    (if (i32.or (i32.eq (local.get $a) (i32.const -1)) (i32.eq (local.get $b) (i32.const -1)))
      (then (return (i32.const 0))))
    (if (i32.eqz (call $dim_subset (local.get $a) (local.get $b) (i32.const 0)
                                   (local.get $cfr) (local.get $cfrlen) (local.get $pfr) (local.get $pfrlen)))
      (then (return (i32.const 0))))
    ;; operations — id-scope, no frame
    (local.set $a (call $map_find (local.get $cg) (i32.const 0x461380) (i32.const 10)))
    (local.set $b (call $map_find (local.get $pg) (i32.const 0x461380) (i32.const 10)))
    (if (i32.or (i32.eq (local.get $a) (i32.const -1)) (i32.eq (local.get $b) (i32.const -1)))
      (then (return (i32.const 0))))
    (if (i32.eqz (call $dim_subset (local.get $a) (local.get $b) (i32.const 0)
                                   (local.get $cfr) (local.get $cfrlen) (local.get $pfr) (local.get $pfrlen)))
      (then (return (i32.const 0))))
    ;; resources — THE framed dimension, and the only one
    (local.set $a (call $map_find (local.get $cg) (i32.const 0x461340) (i32.const 9)))
    (local.set $b (call $map_find (local.get $pg) (i32.const 0x461340) (i32.const 9)))
    (if (i32.ne (local.get $a) (i32.const -1))
      (then
        (if (i32.eq (local.get $b) (i32.const -1)) (then (return (i32.const 0))))
        (if (i32.eqz (call $dim_subset (local.get $a) (local.get $b) (i32.const 1)
                                       (local.get $cfr) (local.get $cfrlen) (local.get $pfr) (local.get $pfrlen)))
          (then (return (i32.const 0))))))
    ;; peers — id-scope; absent defaults to {include:[local_peer_id]} on BOTH sides, so an
    ;; absent-vs-absent pair is trivially a subset and needs no synthesised map.
    (local.set $a (call $map_find (local.get $cg) (i32.const 0x461980) (i32.const 5)))
    (local.set $b (call $map_find (local.get $pg) (i32.const 0x461980) (i32.const 5)))
    (if (i32.ne (local.get $a) (i32.const -1))
      (then
        (if (i32.eq (local.get $b) (i32.const -1)) (then (return (i32.const 0))))
        (if (i32.eqz (call $dim_subset (local.get $a) (local.get $b) (i32.const 0)
                                       (local.get $cfr) (local.get $cfrlen) (local.get $pfr) (local.get $pfrlen)))
          (then (return (i32.const 0))))))
    ;; constraints: parent keys must be retained; allowances: child keys must pre-exist
    (if (i32.eqz (call $map_attenuated (call $map_find (local.get $pg) (i32.const 0x463f00) (i32.const 11))
                                       (call $map_find (local.get $cg) (i32.const 0x463f00) (i32.const 11))))
      (then (return (i32.const 0))))
    (call $map_attenuated (call $map_find (local.get $cg) (i32.const 0x463e80) (i32.const 10))
                          (call $map_find (local.get $pg) (i32.const 0x463e80) (i32.const 10))))

  ;; §5.6 is_attenuated(child, parent) with the per-link §5.5a frames.
  (func $is_attenuated (param $ctd i32) (param $ptd i32)
                       (param $cfr i32) (param $cfrlen i32) (param $pfr i32) (param $pfrlen i32) (result i32)
    (local $cg i32) (local $pg i32) (local $n i64) (local $i i64) (local $p i32) (local $g i32)
    (local $qn i64) (local $qi i64) (local $q i32) (local $hit i32) (local $f i32) (local $pex i64)
    (local.set $cg (call $map_find (local.get $ctd) (i32.const 0x4611c0) (i32.const 6)))
    (local.set $pg (call $map_find (local.get $ptd) (i32.const 0x4611c0) (i32.const 6)))
    (if (i32.eq (local.get $cg) (i32.const -1)) (then (return (i32.const 0))))
    (if (i32.eq (local.get $pg) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $p (call $rd_head (local.get $cg)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $g (local.get $p))
      (local.set $hit (i32.const 0))
      (local.set $q (call $rd_head (local.get $pg)))
      (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
      (local.set $qn (global.get $g_arg))
      (local.set $qi (i64.const 0))
      (block $qdone (loop $qL
        (br_if $qdone (i64.ge_u (local.get $qi) (local.get $qn)))
        (if (call $grant_subset_framed (local.get $g) (local.get $q)
                                       (local.get $cfr) (local.get $cfrlen) (local.get $pfr) (local.get $pfrlen))
          (then (local.set $hit (i32.const 1)) (br $qdone)))
        (local.set $q (call $skip (local.get $q)))
        (local.set $qi (i64.add (local.get $qi) (i64.const 1)))
        (br $qL)))
      (if (i32.eqz (local.get $hit)) (then (return (i32.const 0))))
      (local.set $p (call $skip (local.get $g)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    ;; Expiration nil-vs-finite (§5.6, normative): a child with NO expires_at is infinite, and
    ;; infinite exceeds any finite parent. The permissive reading — treat the absent child
    ;; field as "inherits the parent's" — is the one a reader reaches by accident and is
    ;; explicitly non-conformant.
    (local.set $f (call $map_find (local.get $ptd) (i32.const 0x462180) (i32.const 10)))
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (i32.const 1))))
    (drop (call $rd_head (local.get $f)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (local.set $pex (global.get $g_arg))
    (local.set $f (call $map_find (local.get $ctd) (i32.const 0x462180) (i32.const 10)))
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (i32.const 0))))
    (drop (call $rd_head (local.get $f)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (i64.le_u (global.get $g_arg) (local.get $pex)))

  ;; §5.5 check_delegation_caveats(parent, child, depth). Absent block → nothing to enforce.
  (func $caveats_ok (param $ptd i32) (param $ctd i32) (param $depth i32) (result i32)
    (local $cav i32) (local $f i32) (local $lim i64) (local $cex i64) (local $ccr i64)
    (local.set $cav (call $map_find (local.get $ptd) (i32.const 0x464680) (i32.const 18)))
    (if (i32.eq (local.get $cav) (i32.const -1)) (then (return (i32.const 1))))
    ;; no_delegation
    (local.set $f (call $map_find (local.get $cav) (i32.const 0x463b80) (i32.const 13)))
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.and (i32.eq (global.get $g_major) (i32.const 7))
                         (i64.eq (global.get $g_arg) (i64.const 21)))     ;; CBOR true
              (then (return (i32.const 0))))))
    ;; max_delegation_depth — denied when depth >= limit
    (local.set $f (call $map_find (local.get $cav) (i32.const 0x463c00) (i32.const 20)))
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
            (if (i64.ge_u (i64.extend_i32_u (local.get $depth)) (global.get $g_arg))
              (then (return (i32.const 0))))))
    ;; max_delegation_ttl — an infinite child exceeds any finite limit
    (local.set $f (call $map_find (local.get $cav) (i32.const 0x463bc0) (i32.const 18)))
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (i32.const 1))))
    (drop (call $rd_head (local.get $f)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (local.set $lim (global.get $g_arg))
    (local.set $f (call $map_find (local.get $ctd) (i32.const 0x462180) (i32.const 10)))
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (i32.const 0))))
    (drop (call $rd_head (local.get $f)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (local.set $cex (global.get $g_arg))
    (local.set $f (call $map_find (local.get $ctd) (i32.const 0x461280) (i32.const 10)))
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (i32.const 0))))
    (drop (call $rd_head (local.get $f)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (if (i64.lt_u (local.get $cex) (global.get $g_arg)) (then (return (i32.const 1))))
    (i64.le_u (i64.sub (local.get $cex) (global.get $g_arg)) (local.get $lim)))

  ;; CAP-6a + temporal validity for ONE link, against the once-sampled `now`.
  ;;
  ;; The representability test runs FIRST and is the whole point: an accessor that answers
  ;; "nothing" for both an ABSENT field and a PRESENT-but-not-uint64 one collapses MALFORMED
  ;; into ABSENT — and absent means "no expiry", so the fail-open reading hands an immortal
  ;; capability to whoever sent the malformed value. Here the two are distinguishable by
  ;; construction: $map_find answers ABSENT, $g_major answers REPRESENTABLE. CAP-6a covers
  ;; THREE fields, and created_at is the one an audit shaped around expiry checks misses.
  ;; (A bignum can only reach a peer as a major-type-6 tag and is refused at decode; what
  ;; arrives here is the negative form, major type 1.)
  (func $link_temporal_ok (param $td i32) (param $now i64) (result i32)
    (local $f i32)
    (local.set $f (call $map_find (local.get $td) (i32.const 0x461280) (i32.const 10)))     ;; created_at
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x4621c0) (i32.const 10)))     ;; not_before
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
            (if (i64.lt_u (local.get $now) (global.get $g_arg)) (then (return (i32.const 0))))))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x462180) (i32.const 10)))     ;; expires_at
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
            ;; §5.6 CAP-6: expiry is an EXCLUSIVE upper bound — expired when now >= expires_at.
            ;; This pairs with ttl_ms:0 minting expires_at == created_at, which must be expired
            ;; at every observable instant rather than valid for one and racing.
            (if (i64.ge_u (local.get $now) (global.get $g_arg)) (then (return (i32.const 0))))))
    (i32.const 1))

  ;; §3.6 / §5.5 K-of-N multi-granter (M3 structure, M4 threshold, M6 local participation).
  ;; $g is the granter VALUE pointer (a map {signers, threshold}); $target is the link's own
  ;; content hash, which is what each signer signs. Returns 1 only when the quorum is met AND
  ;; the local peer is one of the signers that actually signed — M6 generalizes "root granter
  ;; must be the local peer" to "the local peer must have jointly authorized this root", which
  ;; is what keeps a K-of-N cap locally rooted rather than universally usable.
  (func $multi_granter_ok (param $g i32) (param $incl i32) (param $target i32) (result i32)
    (local $sg i32) (local $th i32) (local $n i64) (local $i i64) (local $j i64) (local $thr i64)
    (local $p i32) (local $q i32) (local $sp i32) (local $qp i32) (local $valid i64) (local $localhit i32)
    (local $ident i32) (local $d i32) (local $pk i32) (local $pkp i32) (local $sig i32)
    (local.set $sg (call $map_find (local.get $g) (i32.const 0x464080) (i32.const 7)))       ;; signers
    (if (i32.eq (local.get $sg) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $p (call $rd_head (local.get $sg)))
    (if (i32.ne (global.get $g_major) (i32.const 4)) (then (return (i32.const 0))))
    (local.set $n (global.get $g_arg))
    (if (i64.lt_u (local.get $n) (i64.const 2)) (then (return (i32.const 0))))               ;; M3: >= 2 signers
    (local.set $th (call $map_find (local.get $g) (i32.const 0x4640c0) (i32.const 9)))       ;; threshold
    (if (i32.eq (local.get $th) (i32.const -1)) (then (return (i32.const 0))))
    (drop (call $rd_head (local.get $th)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (return (i32.const 0))))
    (local.set $thr (global.get $g_arg))
    (if (i64.lt_u (local.get $thr) (i64.const 2)) (then (return (i32.const 0))))             ;; M3: 2 <= threshold
    (if (i64.gt_u (local.get $thr) (local.get $n)) (then (return (i32.const 0))))            ;; M3: threshold <= |signers|
    ;; M3: no duplicate signers — otherwise one key could satisfy a K-of-N by being listed K times
    (local.set $p (call $rd_head (local.get $sg)))
    (block $ddone (loop $dL
      (br_if $ddone (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $sp (call $rd_head (local.get $p)))
      (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (i32.const 0))))
      (local.set $p (i32.add (local.get $sp) (i32.const 33)))
      (local.set $q (local.get $p))
      (local.set $j (i64.add (local.get $i) (i64.const 1)))
      (block $idone (loop $iL
        (br_if $idone (i64.ge_u (local.get $j) (local.get $n)))
        (local.set $qp (call $rd_head (local.get $q)))
        (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (i32.const 0))))
        (local.set $q (i32.add (local.get $qp) (i32.const 33)))
        (if (call $streq (local.get $sp) (i32.const 33) (local.get $qp) (i32.const 33))
          (then (return (i32.const 0))))
        (local.set $j (i64.add (local.get $j) (i64.const 1)))
        (br $iL)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $dL)))
    ;; M4 + M6: count signatures that actually verify, and note whether one of them is ours
    (local.set $i (i64.const 0))
    (local.set $p (call $rd_head (local.get $sg)))
    (block $vdone (loop $vL
      (br_if $vdone (i64.ge_u (local.get $i) (local.get $n)))
      (local.set $sp (call $rd_head (local.get $p)))
      (local.set $p (i32.add (local.get $sp) (i32.const 33)))
      (block $next
        (local.set $ident (call $included_find_by_key (local.get $incl) (local.get $sp)))
        (br_if $next (i32.eqz (local.get $ident)))
        (local.set $d (call $map_find (local.get $ident) (i32.const 0x460010) (i32.const 4)))
        (br_if $next (i32.eq (local.get $d) (i32.const -1)))
        (local.set $pk (call $map_find (local.get $d) (i32.const 0x461080) (i32.const 10)))
        (br_if $next (i32.eq (local.get $pk) (i32.const -1)))
        (local.set $pkp (call $rd_head (local.get $pk)))
        (local.set $sig (call $find_req_sig (local.get $incl) (local.get $sp) (local.get $target)))
        (br_if $next (i32.eqz (local.get $sig)))
        (br_if $next (call $ed_verify (local.get $pkp) (local.get $target) (i32.const 33) (local.get $sig)))
        (local.set $valid (i64.add (local.get $valid) (i64.const 1)))
        (if (call $streq (local.get $sp) (i32.const 33) (i32.const 0x440000) (i32.const 33))
          (then (local.set $localhit (i32.const 1)))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $vL)))
    (if (i64.lt_u (local.get $valid) (local.get $thr)) (then (return (i32.const 0))))
    (local.get $localhit))

  ;; §5.2 cap-class (403 / 401 unresolvable_grantee) + §5.5 delegation-chain verification.
  ;;
  ;; Walks capability → parent → … → root, validating EVERY link: content-hash integrity,
  ;; revocation, grantee resolution, temporal validity (CAP-6a representability first), and
  ;; the granter's signature. For every non-root link it additionally checks the parent
  ;; linkage (parent.grantee == child.granter), §5.6 attenuation under §5.5a per-link granter
  ;; frames, and the parent's delegation caveats. The ROOT's granter must be this peer —
  ;; that check has not gone away, it has moved to the end of the walk where it belongs
  ;; instead of standing in for the walk.
  (func $verify_cap (param $edp i32) (param $in i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $capp i32) (local $ap i32) (local $incl i32) (local $cur i32) (local $depth i32)
    (local $tok i32) (local $td i32) (local $tdlen i32) (local $now i64)
    (local $gee i32) (local $gp i32) (local $gpeer i32) (local $gt i32) (local $gtp i32) (local $gtl i32)
    (local $gtr i32) (local $grp i32) (local $gpd i32) (local $gpk i32) (local $gpkp i32) (local $sig i32)
    (local $par i32) (local $ctd i32)
    (local.set $capp (call $map_find (local.get $edp) (i32.const 0x462040) (i32.const 10)))
    (if (i32.eq (local.get $capp) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $capp (call $rd_head (local.get $capp)))
    (local.set $ap (call $map_find (local.get $edp) (i32.const 0x462000) (i32.const 6)))
    (if (i32.eq (local.get $ap) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ap (call $rd_head (local.get $ap)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; §5.5 v7.76: `t` is sampled ONCE per verdict and never re-sampled per link — otherwise
    ;; the verdict depends on wall-clock drift within a single walk.
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $now (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    (local.set $cur (local.get $capp))
    (block $chain_done (loop $walk
      (local.set $tok (call $included_find_by_key (local.get $incl) (local.get $cur)))
      (if (i32.eqz (local.get $tok)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $td (call $map_find (local.get $tok) (i32.const 0x460010) (i32.const 4)))
      (if (i32.eq (local.get $td) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $tdlen (i32.sub (call $skip (local.get $td)) (local.get $td)))
      ;; integrity: the link's data must hash to the hash we followed to reach it
      (drop (call $content_hash (i32.const 0x461540) (i32.const 23) (local.get $td) (local.get $tdlen) (i32.const 0x920280)))
      (if (i32.eqz (call $streq (i32.const 0x920280) (i32.const 33) (local.get $cur) (i32.const 33)))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; §6.9a — revocation is per-link: revoking an intermediate kills everything under it
      (if (call $store_get (i32.const 0x978000) (call $revoc_path (local.get $cur)))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; grantee must resolve to a present system/peer — per link, not just at the leaf
      (local.set $gee (call $map_find (local.get $td) (i32.const 0x461200) (i32.const 7)))
      (if (i32.eq (local.get $gee) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gp (call $rd_head (local.get $gee)))
      (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gpeer (call $included_find_by_key (local.get $incl) (local.get $gp)))
      (if (i32.eqz (local.get $gpeer)) (then (return (call $err_unresg (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gt (call $map_find (local.get $gpeer) (i32.const 0x460020) (i32.const 4)))
      (if (i32.eq (local.get $gt) (i32.const -1)) (then (return (call $err_unresg (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gtp (call $rd_head (local.get $gt)))
      (local.set $gtl (i32.wrap_i64 (global.get $g_arg)))
      (if (i32.eqz (call $streq (local.get $gtp) (local.get $gtl) (i32.const 0x4614c0) (i32.const 11)))
        (then (return (call $err_unresg (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; linkage: the LEAF is granted to the request author; every parent is granted to the
      ;; granter of the link below it. `$g_pgee` carries the child's granter across the hop.
      (if (i32.eqz (local.get $depth))
        (then (if (i32.eqz (call $streq (local.get $gp) (i32.const 33) (local.get $ap) (i32.const 33)))
                (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen))))))
        (else (if (i32.eqz (call $streq (local.get $gp) (i32.const 33) (i32.const 0x9A0800) (i32.const 33)))
                (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
      (if (i32.eqz (call $link_temporal_ok (local.get $td) (local.get $now)))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; granter
      (local.set $gtr (call $map_find (local.get $td) (i32.const 0x461240) (i32.const 7)))
      (if (i32.eq (local.get $gtr) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $grp (call $rd_head (local.get $gtr)))
      ;; §3.6 K-of-N multi-granter.
      (if (i32.eq (global.get $g_major) (i32.const 5))
        (then
          ;; M3 structural validity runs BEFORE any signature verification, so a violation
          ;; surfaces as 403 capability_denied rather than as a signature failure. Multi-sig
          ;; is ROOT-ONLY: a multi-granter link carrying a parent is structurally invalid.
          (if (i32.ne (call $map_find (local.get $td) (i32.const 0x462140) (i32.const 6)) (i32.const -1))
            (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
          ;; A quorum root has no single granter peer_id, so §5.5a has no frame to canonicalize
          ;; its resource patterns against. Rather than invent one, this peer accepts a K-of-N
          ;; root only when it is the capability actually PRESENTED (depth 0) — where no
          ;; attenuation comparison is needed. A chain whose root is K-of-N is refused, and
          ;; that limit is written here rather than left to be discovered.
          (if (local.get $depth) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
          (if (i32.eqz (call $multi_granter_ok (local.get $gtr) (local.get $incl) (local.get $cur)))
            (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
          (br $chain_done)))
      (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; signature over THIS link, by THIS link's granter
      (local.set $gpeer (call $included_find_by_key (local.get $incl) (local.get $grp)))
      (if (i32.eqz (local.get $gpeer)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gpd (call $map_find (local.get $gpeer) (i32.const 0x460010) (i32.const 4)))
      (if (i32.eq (local.get $gpd) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gpk (call $map_find (local.get $gpd) (i32.const 0x461080) (i32.const 10)))
      (if (i32.eq (local.get $gpk) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $gpkp (call $rd_head (local.get $gpk)))
      (local.set $sig (call $find_req_sig (local.get $incl) (local.get $grp) (local.get $cur)))
      (if (i32.eqz (local.get $sig)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $ed_verify (local.get $gpkp) (local.get $cur) (i32.const 33) (local.get $sig))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; this link's §5.5a frame = its granter's peer_id
      (if (i32.eqz (call $peerid_of (local.get $incl) (local.get $grp) (i32.const 0x9A0100) (i32.const 0x9A0180)))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; attenuation + caveats against the child we arrived from
      (if (local.get $depth)
        (then
          (if (i32.eqz (call $is_attenuated (local.get $ctd) (local.get $td)
                                            (i32.const 0x9A0000) (i32.load (i32.const 0x9A0080))
                                            (i32.const 0x9A0100) (i32.load (i32.const 0x9A0180))))
            (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
          (if (i32.eqz (call $caveats_ok (local.get $td) (local.get $ctd) (i32.sub (local.get $depth) (i32.const 1))))
            (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
      ;; root?
      (local.set $par (call $map_find (local.get $td) (i32.const 0x462140) (i32.const 6)))
      (if (i32.eq (local.get $par) (i32.const -1))
        (then
          ;; §5.5 root trust: the chain must terminate at a capability this peer granted.
          (if (i32.eqz (call $streq (local.get $grp) (i32.const 33) (i32.const 0x440000) (i32.const 33)))
            (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
          (br $chain_done)))
      ;; carry the child state across the hop: its data, its granter, and its frame
      (local.set $ctd (local.get $td))
      (memory.copy (i32.const 0x9A0800) (local.get $grp) (i32.const 33))
      (memory.copy (i32.const 0x9A0000) (i32.const 0x9A0100) (i32.const 128))
      (i32.store (i32.const 0x9A0080) (i32.load (i32.const 0x9A0180)))
      (local.set $cur (call $rd_head (local.get $par)))
      (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (local.set $depth (i32.add (local.get $depth) (i32.const 1)))
      ;; §5.5 collect_authority_chain bounds depth at 64; $chain_depth_check already answers
      ;; 400 chain_depth_exceeded ahead of this walk, so this is the belt to that braces —
      ;; it exists so the loop cannot run unbounded if the walk is ever reached by another path.
      (if (i32.gt_u (local.get $depth) (i32.const 64))
        (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
      (br $walk)))
    (i32.const 0))

  ;; §5.2 grant-scope (403): token temporal-valid + some grant covers op×handler×target.
  (func $verify_scope (param $edp i32) (param $in i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $cap i32) (local $capp i32) (local $incl i32) (local $tok i32) (local $td i32)
    (local $op i32) (local $opp i32) (local $oplen i32) (local $res i32) (local $ta i32) (local $tgp i32) (local $tglen i32)
    (local $f i32) (local $ms i64)
    (call $derive_handler (local.get $edp))
    (local.set $cap (call $map_find (local.get $edp) (i32.const 0x462040) (i32.const 10)))
    (if (i32.eq (local.get $cap) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $capp (call $rd_head (local.get $cap)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $tok (call $included_find_by_key (local.get $incl) (local.get $capp)))
    (if (i32.eqz (local.get $tok)) (then (return (i32.const 0))))
    (local.set $td (call $map_find (local.get $tok) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $td) (i32.const -1)) (then (return (i32.const 0))))
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x462180) (i32.const 10)))          ;; expires_at
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i64.gt_u (local.get $ms) (global.get $g_arg)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
    (local.set $f (call $map_find (local.get $td) (i32.const 0x4621c0) (i32.const 10)))          ;; not_before
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i64.lt_u (local.get $ms) (global.get $g_arg)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
    (local.set $op (call $map_find (local.get $edp) (i32.const 0x4600c0) (i32.const 9)))         ;; operation
    (if (i32.eq (local.get $op) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $opp (call $rd_head (local.get $op)))
    (local.set $oplen (i32.wrap_i64 (global.get $g_arg)))
    (local.set $res (call $map_find (local.get $edp) (i32.const 0x462080) (i32.const 8)))        ;; resource
    (if (i32.eq (local.get $res) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ta (call $map_find (local.get $res) (i32.const 0x4620c0) (i32.const 7)))         ;; targets
    (if (i32.eq (local.get $ta) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tgp (call $rd_head (local.get $ta)))
    (if (i64.eqz (global.get $g_arg)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tgp (call $rd_head (local.get $tgp)))
    (local.set $tglen (i32.wrap_i64 (global.get $g_arg)))
    ;; §5.5a frame for the DISPATCH surface: the presented cap's own granter. Derived here
    ;; rather than assumed to be the local peer — they are byte-identical for every
    ;; self-issued capability, which is exactly why framing against the verifier stays
    ;; latent until a foreign-granted cap arrives.
    (local.set $f (call $map_find (local.get $td) (i32.const 0x461240) (i32.const 7)))          ;; granter
    (if (i32.eq (local.get $f) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $f (call $rd_head (local.get $f)))
    (if (i32.eq (global.get $g_major) (i32.const 5))
      (then
        ;; §3.6 K-of-N root: there is no single granter, so §5.5a has no granter peer_id to
        ;; frame against. The local peer is the correct frame here and not a fallback — M6
        ;; already required that the local peer be in the signer set AND have signed, and
        ;; §5.5 says a quorum cap's "subsequent use is locally rooted". The quorum authorized
        ;; issuance; the namespace the patterns name is this peer's.
        (memory.copy (i32.const 0x9A1200) (i32.const 0x420200) (i32.load (i32.const 0x4202F0)))
        (i32.store (i32.const 0x9A1280) (i32.load (i32.const 0x4202F0))))
      (else
        (if (i32.eqz (call $peerid_of (local.get $incl) (local.get $f) (i32.const 0x9A1200) (i32.const 0x9A1280)))
          (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))))
    (if (call $grant_scope_ok (local.get $td) (local.get $tgp) (local.get $tglen) (local.get $opp) (local.get $oplen)
                              (i32.const 0x9A1200) (i32.load (i32.const 0x9A1280))) (then (return (i32.const 0))))
    (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))

  ;; 200 EXECUTE_RESPONSE {result:<blob>, status:200, request_id} wrapping a stored entity blob.
  (func $build_get_ok (param $out i32) (param $blob i32) (param $bloblen i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $dlen i32)
    (global.set $g_wp (i32.const 0x974000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))  (call $w_bytes (local.get $blob) (local.get $bloblen))   ;; result
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (i64.const 200))
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (local.get $rid) (local.get $rlen))
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x974000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x974000) (local.get $dlen) (i32.const 0x920380)))
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x460000) (i32.const 4))
    (call $w_entity (i32.const 0x460040) (i32.const 32) (i32.const 0x974000) (local.get $dlen) (i32.const 0x920380))
    (i32.sub (global.get $g_wp) (local.get $out)))

  (func $w_null (i32.store8 (global.get $g_wp) (i32.const 0xf6)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1))))

  ;; true iff the stored entity blob is a system/deletion-marker (its bound path is logically
  ;; deleted → a listing MUST omit it, §6.3 / §9.5a CORE-TREE-DELETE-1).
  (func $is_delmarker (param $blob i32) (result i32)
    (local $t i32)
    (local.set $t (call $map_find (local.get $blob) (i32.const 0x460020) (i32.const 4)))   ;; type
    (if (i32.eq (local.get $t) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $t (call $rd_head (local.get $t)))
    (call $streq (local.get $t) (i32.wrap_i64 (global.get $g_arg)) (i32.const 0x464700) (i32.const 22)))

  ;; true iff store entry $e is a live child under $prefix (path strictly under prefix AND the
  ;; bound entity is not a deletion marker).
  (func $listing_include (param $e i32) (param $prefix i32) (param $plen i32) (result i32)
    (local $pl i32) (local $islocal i32)
    (local.set $pl (i32.load (i32.add (local.get $e) (i32.const 4))))
    (if (i32.eqz (i32.and (i32.gt_u (local.get $pl) (local.get $plen))
                          (call $streq (i32.load (local.get $e)) (local.get $plen) (local.get $prefix) (local.get $plen))))
      (then (return (i32.const 0))))
    ;; §1.4 namespace isolation: a local (peer-relative) listing prefix must not surface foreign
    ;; absolute keys ('/{other_peer}/...'); a foreign listing has a '/'-leading prefix and matches.
    (local.set $islocal (i32.const 1))
    (if (local.get $plen) (then (if (i32.eq (i32.load8_u (local.get $prefix)) (i32.const 0x2f)) (then (local.set $islocal (i32.const 0))))))
    (if (i32.and (local.get $islocal) (i32.eq (i32.load8_u (i32.load (local.get $e))) (i32.const 0x2f)))
      (then (return (i32.const 0))))
    (i32.eqz (call $is_delmarker (i32.load (i32.add (local.get $e) (i32.const 8))))))

  ;; set $g_chp/$g_chlen to the IMMEDIATE child segment of store-entry $e under a $plen-byte prefix
  ;; (the remainder truncated at its first '/'), i.e. the directory-style child name.
  (func $child_of (param $e i32) (param $plen i32)
    (local $rem i32) (local $remlen i32) (local $k i32)
    (local.set $rem (i32.add (i32.load (local.get $e)) (local.get $plen)))
    (local.set $remlen (i32.sub (i32.load (i32.add (local.get $e) (i32.const 4))) (local.get $plen)))
    (global.set $g_chp (local.get $rem))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $k) (local.get $remlen)))
      (br_if $d (i32.eq (i32.load8_u (i32.add (local.get $rem) (local.get $k))) (i32.const 0x2f)))
      (local.set $k (i32.add (local.get $k) (i32.const 1))) (br $l)))
    (global.set $g_chlen (local.get $k)))

  ;; true iff store-entry index $idx is the FIRST included entry with its immediate-child segment
  ;; (dedup: many keys under a prefix collapse to one directory child). Leaves $g_chp/$g_chlen unset.
  (func $child_first (param $idx i32) (param $prefix i32) (param $plen i32) (result i32)
    (local $chp i32) (local $chlen i32) (local $j i32) (local $ej i32)
    (call $child_of (i32.add (i32.const 0xA00010) (i32.mul (local.get $idx) (i32.const 16))) (local.get $plen))
    (local.set $chp (global.get $g_chp)) (local.set $chlen (global.get $g_chlen))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $j) (local.get $idx)))
      (local.set $ej (i32.add (i32.const 0xA00010) (i32.mul (local.get $j) (i32.const 16))))
      (if (call $listing_include (local.get $ej) (local.get $prefix) (local.get $plen))
        (then
          (call $child_of (local.get $ej) (local.get $plen))
          (if (i32.and (i32.eq (global.get $g_chlen) (local.get $chlen))
                       (call $streq (global.get $g_chp) (local.get $chlen) (local.get $chp) (local.get $chlen)))
            (then (return (i32.const 0))))))
      (local.set $j (i32.add (local.get $j) (i32.const 1))) (br $l)))
    (i32.const 1))

  ;; serve a trailing-slash / root listing: a system/tree/listing entity whose data.entries maps
  ;; each IMMEDIATE CHILD name (deduped) under $prefix → null. §6.3 directory semantics. Unsorted.
  (func $serve_listing (param $out i32) (param $prefix i32) (param $plen i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $c i32) (local $i i32) (local $e i32) (local $nchild i32) (local $dlen i32) (local $elen i32)
    (local.set $c (i32.load (i32.const 0xA00000)))
    (block $cd (loop $cl
      (br_if $cd (i32.ge_u (local.get $i) (local.get $c)))
      (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $i) (i32.const 16))))
      (if (i32.and (call $listing_include (local.get $e) (local.get $prefix) (local.get $plen))
                   (call $child_first (local.get $i) (local.get $prefix) (local.get $plen)))
        (then (local.set $nchild (i32.add (local.get $nchild) (i32.const 1)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $cl)))
    (global.set $g_wp (i32.const 0x975000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x462900) (i32.const 7))    ;; "entries"
    (call $w_map (i64.extend_i32_u (local.get $nchild)))
    (local.set $i (i32.const 0))
    (block $ed (loop $el
      (br_if $ed (i32.ge_u (local.get $i) (local.get $c)))
      (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $i) (i32.const 16))))
      (if (i32.and (call $listing_include (local.get $e) (local.get $prefix) (local.get $plen))
                   (call $child_first (local.get $i) (local.get $prefix) (local.get $plen)))
        (then
          (call $child_of (local.get $e) (local.get $plen))
          (call $w_text (global.get $g_chp) (global.get $g_chlen))
          (call $w_null)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $el)))
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x975000)))
    (drop (call $content_hash (i32.const 0x462880) (i32.const 19) (i32.const 0x975000) (local.get $dlen) (i32.const 0x9203c0)))
    (global.set $g_wp (i32.const 0x976000))
    (call $w_entity (i32.const 0x462880) (i32.const 19) (i32.const 0x975000) (local.get $dlen) (i32.const 0x9203c0))
    (local.set $elen (i32.sub (global.get $g_wp) (i32.const 0x976000)))
    (call $build_get_ok (local.get $out) (i32.const 0x976000) (local.get $elen) (local.get $rid) (local.get $rlen)))

  ;; is a handler registered? true iff a system/handler/<handler> entity is in the store.
  (func $handler_registered (param $hp i32) (param $hl i32) (result i32)
    (global.set $g_wp (i32.const 0x977000))
    (call $w_bytes (i32.const 0x462500) (i32.const 15))   ;; "system/handler/"
    (call $w_bytes (local.get $hp) (local.get $hl))
    (i32.ne (call $store_get (i32.const 0x977000) (i32.add (i32.const 15) (local.get $hl))) (i32.const 0)))

  ;; is $op a known operation of handler <hp,hl>? (present in its interface's operations map)
  (func $op_known (param $hp i32) (param $hl i32) (param $op i32) (param $oplen i32) (result i32)
    (local $blob i32) (local $d i32) (local $ops i32)
    (global.set $g_wp (i32.const 0x977000))
    (call $w_bytes (i32.const 0x462500) (i32.const 15))
    (call $w_bytes (local.get $hp) (local.get $hl))
    (local.set $blob (call $store_get (i32.const 0x977000) (i32.add (i32.const 15) (local.get $hl))))
    (if (i32.eqz (local.get $blob)) (then (return (i32.const 0))))
    (local.set $d (call $map_find (local.get $blob) (i32.const 0x460010) (i32.const 4)))       ;; data
    (if (i32.eq (local.get $d) (i32.const -1)) (then (return (i32.const 0))))
    (local.set $ops (call $map_find (local.get $d) (i32.const 0x461380) (i32.const 10)))       ;; operations
    (if (i32.eq (local.get $ops) (i32.const -1)) (then (return (i32.const 0))))
    (i32.ne (call $map_find (local.get $ops) (local.get $op) (local.get $oplen)) (i32.const -1)))

  ;; §6.5/§6.2 resolution-first dispatch for an authenticated EXECUTE with no dedicated handler:
  ;; §5.2 auth (401) → resolve handler (404) → op-existence (501, precedes permission per the
  ;; §6.2 status table) → §5.2 cap+scope (403) → else known+permitted but unimplemented → 501.
  (func $serve_auth_op (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (param $op i32) (param $oplen i32) (result i32)
    (local $e i32)
    (local.set $e (call $chain_depth_check (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (call $derive_handler (local.get $edp))
    (if (i32.eqz (call $handler_registered (global.get $g_hptr) (global.get $g_hlen)))
      (then (return (call $build_error (local.get $out) (i32.const 0x461900) (i32.const 17) (i32.const 404) (local.get $rid) (local.get $rlen)))))  ;; handler_not_found
    (if (i32.eqz (call $op_known (global.get $g_hptr) (global.get $g_hlen) (local.get $op) (local.get $oplen)))
      (then (return (call $build_error (local.get $out) (i32.const 0x462a80) (i32.const 21) (i32.const 501) (local.get $rid) (local.get $rlen)))))  ;; unsupported_operation
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (call $build_error (local.get $out) (i32.const 0x462a80) (i32.const 21) (i32.const 501) (local.get $rid) (local.get $rlen)))  ;; known+permitted, unimplemented

  ;; serve a system/tree get: §9.1/§5.2 gates → parse target → store lookup → 200 / 404 / 400.
  (func $serve_tree_get (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $res i32) (local $ta i32) (local $tp i32) (local $tlen i32) (local $blob i32)
    (local.set $e (call $chain_depth_check (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $res (call $map_find (local.get $edp) (i32.const 0x462080) (i32.const 8)))
    (if (i32.eq (local.get $res) (i32.const -1)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ta (call $map_find (local.get $res) (i32.const 0x4620c0) (i32.const 7)))
    (if (i32.eq (local.get $ta) (i32.const -1)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tp (call $rd_head (local.get $ta)))
    (if (i64.eqz (global.get $g_arg)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tp (call $rd_head (local.get $tp)))
    (local.set $tlen (i32.wrap_i64 (global.get $g_arg)))
    (if (i32.eqz (call $path_valid (local.get $tp) (local.get $tlen)))
      (then (return (call $build_error (local.get $out) (i32.const 0x4622c0) (i32.const 12) (i32.const 400) (local.get $rid) (local.get $rlen)))))
    (call $canon_path (local.get $tp) (local.get $tlen))   ;; §1.4 canonical store key
    (local.set $tp (global.get $g_cpp)) (local.set $tlen (global.get $g_cplen))
    (if (i32.eqz (local.get $tlen)) (then (return (call $serve_listing (local.get $out) (local.get $tp) (i32.const 0) (local.get $rid) (local.get $rlen)))))   ;; root listing
    (if (i32.eq (i32.load8_u (i32.add (local.get $tp) (i32.sub (local.get $tlen) (i32.const 1)))) (i32.const 0x2f))
      (then (return (call $serve_listing (local.get $out) (local.get $tp) (local.get $tlen) (local.get $rid) (local.get $rlen)))))   ;; prefix listing
    (local.set $blob (call $store_get (local.get $tp) (local.get $tlen)))
    (if (i32.eqz (local.get $blob)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (call $build_get_ok (local.get $out) (local.get $blob) (global.get $s_blen) (local.get $rid) (local.get $rlen)))

  ;; 409 hash_mismatch (CAS conflict).
  (func $err_409hm (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x466740) (i32.const 13) (i32.const 409) (local.get $rid) (local.get $rlen)))

  ;; the reserved zero content-hash → 33 bytes all 0x00 (CAS-create sentinel, §3.9).
  (func $is_zero33 (param $p i32) (result i32)
    (local $i i32)
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i) (i32.const 33)))
      (if (i32.load8_u (i32.add (local.get $p) (local.get $i))) (then (return (i32.const 0))))
      (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $l)))
    (i32.const 1))

  ;; remove a path binding from the store index (shift the last entry into the freed slot).
  (func $store_remove (param $tp i32) (param $tlen i32)
    (local $c i32) (local $i i32) (local $e i32) (local $last i32) (local $k i32)
    (local.set $c (i32.load (i32.const 0xA00000)))
    (block $done (loop $L
      (br_if $done (i32.ge_u (local.get $i) (local.get $c)))
      (local.set $e (i32.add (i32.const 0xA00010) (i32.mul (local.get $i) (i32.const 16))))
      (if (i32.and (i32.eq (i32.load (i32.add (local.get $e) (i32.const 4))) (local.get $tlen))
                   (call $streq (i32.load (local.get $e)) (local.get $tlen) (local.get $tp) (local.get $tlen)))
        (then
          (local.set $c (i32.sub (local.get $c) (i32.const 1)))
          (local.set $last (i32.add (i32.const 0xA00010) (i32.mul (local.get $c) (i32.const 16))))
          (block $cp (loop $cl
            (br_if $cp (i32.eq (local.get $k) (i32.const 16)))
            (i32.store (i32.add (local.get $e) (local.get $k)) (i32.load (i32.add (local.get $last) (local.get $k))))
            (local.set $k (i32.add (local.get $k) (i32.const 4))) (br $cl)))
          (i32.store (i32.const 0xA00000) (local.get $c))
          (return)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L))))

  ;; 200 EXECUTE_RESPONSE with a null result (put-remove / no result body).
  (func $build_put_ok (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $dlen i32)
    (global.set $g_wp (i32.const 0x974000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))  (call $w_null)
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (i64.const 200))
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (local.get $rid) (local.get $rlen))
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x974000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x974000) (local.get $dlen) (i32.const 0x920380)))
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x460000) (i32.const 4))
    (call $w_entity (i32.const 0x460040) (i32.const 32) (i32.const 0x974000) (local.get $dlen) (i32.const 0x920380))
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; 400 ambiguous_resource shorthand (register/unregister: != 1 resource target, or a resource
  ;; not under system/handler/).
  (func $err_ambig (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x466980) (i32.const 18) (i32.const 400) (local.get $rid) (local.get $rlen)))
  ;; 400 manifest_pattern_mismatch shorthand.
  (func $err_manifmm (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x4669b0) (i32.const 25) (i32.const 400) (local.get $rid) (local.get $rlen)))
  ;; 403 forbidden_pattern shorthand (§6.2 reserved-pattern register refusal).
  (func $err_forbidpat (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x466c60) (i32.const 17) (i32.const 403) (local.get $rid) (local.get $rlen)))

  ;; §6.2: "system" itself or any "system/..." prefix is reserved for system handlers;
  ;; user-installed handlers MUST NOT register there. $p/$l is the {pattern} tail
  ;; (already stripped of the "system/handler/" resource prefix by $reg_pattern).
  (func $is_reserved_pattern (param $p i32) (param $l i32) (result i32)
    (if (call $streq (local.get $p) (local.get $l) (i32.const 0x466c80) (i32.const 6))   ;; "system"
      (then (return (i32.const 1))))
    (if (i32.lt_u (local.get $l) (i32.const 7)) (then (return (i32.const 0))))
    (call $streq (local.get $p) (i32.const 7) (i32.const 0x466ca0) (i32.const 7)))       ;; "system/" prefix

  ;; parse resource.targets[0] into the register/unregister pattern. Sets $g_rtp/$g_rtlen (the
  ;; full resource `system/handler/{pattern}`) and $g_patp/$g_patlen (the {pattern} tail). Returns
  ;; 0 on success, or a built 400 ambiguous_resource length on any structural failure (missing
  ;; resource/targets, != 1 target, or a target not under `system/handler/`). §6.2 path-as-resource.
  (func $reg_pattern (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $res i32) (local $ta i32) (local $rt i32) (local $rtlen i32)
    (local.set $res (call $map_find (local.get $edp) (i32.const 0x462080) (i32.const 8)))       ;; resource
    (if (i32.eq (local.get $res) (i32.const -1)) (then (return (call $err_ambig (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ta (call $map_find (local.get $res) (i32.const 0x4620c0) (i32.const 7)))        ;; targets
    (if (i32.eq (local.get $ta) (i32.const -1)) (then (return (call $err_ambig (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $rt (call $rd_head (local.get $ta)))                                             ;; array header
    (if (i64.ne (global.get $g_arg) (i64.const 1)) (then (return (call $err_ambig (local.get $out) (local.get $rid) (local.get $rlen)))))  ;; exactly one
    (local.set $rt (call $rd_head (local.get $rt)))                                             ;; first element (text)
    (local.set $rtlen (i32.wrap_i64 (global.get $g_arg)))
    (if (i32.le_u (local.get $rtlen) (i32.const 15)) (then (return (call $err_ambig (local.get $out) (local.get $rid) (local.get $rlen)))))
    (if (i32.eqz (call $streq (local.get $rt) (i32.const 15) (i32.const 0x462500) (i32.const 15)))   ;; "system/handler/"
      (then (return (call $err_ambig (local.get $out) (local.get $rid) (local.get $rlen)))))
    (global.set $g_rtp   (local.get $rt))
    (global.set $g_rtlen (local.get $rtlen))
    (global.set $g_patp   (i32.add (local.get $rt) (i32.const 15)))
    (global.set $g_patlen (i32.sub (local.get $rtlen) (i32.const 15)))
    (i32.const 0))

  ;; §6.13a / §10.1 system/handler `register`: §5.2-authorize (chain-depth → auth → cap → scope,
  ;; the tree-put interior), then execute the five normative writes (§6.2 process_registration):
  ;;   1. interface  @ system/handler/{pattern}          type system/handler/interface
  ;;   2. handler    @ {pattern}                          type system/handler
  ;;   3. grant      @ system/capability/grants/{pattern} type system/capability/token (self-issued)
  ;;   4. grant-sig  @ system/signature/{hex(grant_hash)} type system/signature (§3.5 invariant ptr)
  ;;   (5. types @ system/type/* — optional register-request.types, none in the core gate; omitted.)
  ;; Return 200 system/handler/register-result {grant:<token data>, pattern}. Scratch @0x980000+.
  (func $serve_register (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $params i32) (local $pdata i32) (local $manif i32)
    (local $mp i32) (local $mplen i32) (local $name i32) (local $namelen i32)
    (local $ops i32) (local $opslen i32) (local $scope i32) (local $scopelen i32) (local $ms i64)
    (local $dlen i32) (local $blen i32) (local $gplen i32) (local $splen i32) (local $tdlen i32) (local $rdlen i32)
    (local.set $e (call $chain_depth_check (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $reg_pattern (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    ;; §6.2: refuse a register at a reserved "system"/"system/..." pattern before any
    ;; of the five normative writes below.
    (if (call $is_reserved_pattern (global.get $g_patp) (global.get $g_patlen))
      (then (return (call $err_forbidpat (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; params.data → manifest
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $manif (call $map_find (local.get $pdata) (i32.const 0x4668c0) (i32.const 8)))    ;; manifest
    (if (i32.eq (local.get $manif) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; §6.2: manifest.pattern, if present, MUST equal the resource-derived pattern.
    (local.set $mp (call $map_find (local.get $manif) (i32.const 0x462580) (i32.const 7)))       ;; pattern
    (if (i32.ne (local.get $mp) (i32.const -1))
      (then
        (local.set $mp (call $rd_head (local.get $mp)))
        (local.set $mplen (i32.wrap_i64 (global.get $g_arg)))
        (if (i32.eqz (call $streq (local.get $mp) (local.get $mplen) (global.get $g_patp) (global.get $g_patlen)))
          (then (return (call $err_manifmm (local.get $out) (local.get $rid) (local.get $rlen)))))))
    ;; manifest.name (fallback: the pattern) and manifest.operations (verbatim map).
    (local.set $name (call $map_find (local.get $manif) (i32.const 0x462540) (i32.const 4)))     ;; name
    (if (i32.ne (local.get $name) (i32.const -1))
      (then (local.set $name (call $rd_head (local.get $name))) (local.set $namelen (i32.wrap_i64 (global.get $g_arg))))
      (else (local.set $name (global.get $g_patp)) (local.set $namelen (global.get $g_patlen))))
    (local.set $ops (call $map_find (local.get $manif) (i32.const 0x461380) (i32.const 10)))     ;; operations
    (if (i32.eq (local.get $ops) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $opslen (i32.sub (call $skip (local.get $ops)) (local.get $ops)))
    ;; grant scope = requested_scope (pdata) or manifest.internal_scope (or empty []).
    (local.set $scope (call $map_find (local.get $pdata) (i32.const 0x466910) (i32.const 15)))   ;; requested_scope
    (if (i32.eq (local.get $scope) (i32.const -1))
      (then (local.set $scope (call $map_find (local.get $manif) (i32.const 0x4668f0) (i32.const 14)))))  ;; internal_scope
    ;; ===== WRITE 1: interface entity @ system/handler/{pattern} (= the resource target) =====
    ;; data {name, pattern, operations} (canonical order: name(4) < pattern(7) < operations(10)).
    (global.set $g_wp (i32.const 0x982000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x462540) (i32.const 4))  (call $w_text (local.get $name) (local.get $namelen))
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (global.get $g_patp) (global.get $g_patlen))
    (call $w_text (i32.const 0x461380) (i32.const 10)) (call $w_bytes (local.get $ops) (local.get $opslen))
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x982000)))
    (drop (call $content_hash (i32.const 0x462640) (i32.const 24) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985000)))
    (global.set $g_wp (i32.const 0x983000))
    (call $w_entity (i32.const 0x462640) (i32.const 24) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985000))  ;; system/handler/interface
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x983000)))
    (call $store_put (global.get $g_rtp) (global.get $g_rtlen) (i32.const 0x983000) (local.get $blen))
    ;; ===== WRITE 2: handler entity @ {pattern} — data {interface:<interface_path>} =====
    (global.set $g_wp (i32.const 0x982000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4668b0) (i32.const 9))  (call $w_text (global.get $g_rtp) (global.get $g_rtlen))  ;; interface = system/handler/{pattern}
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x982000)))
    (drop (call $content_hash (i32.const 0x466800) (i32.const 14) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985040)))
    (global.set $g_wp (i32.const 0x983000))
    (call $w_entity (i32.const 0x466800) (i32.const 14) (i32.const 0x982000) (local.get $dlen) (i32.const 0x985040))  ;; system/handler
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x983000)))
    (call $store_put (global.get $g_patp) (global.get $g_patlen) (i32.const 0x983000) (local.get $blen))
    ;; ===== WRITE 3: grant token @ system/capability/grants/{pattern} (self-issued) =====
    ;; token data {grants, grantee, granter, created_at} @0x981000 (retained for the result).
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    (global.set $g_wp (i32.const 0x981000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x4611c0) (i32.const 6))                                            ;; grants
    (if (i32.ne (local.get $scope) (i32.const -1))
      (then (call $w_bytes (local.get $scope) (i32.sub (call $skip (local.get $scope)) (local.get $scope))))
      (else (i32.store8 (global.get $g_wp) (i32.const 0x80)) (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1)))))  ;; []
    (call $w_text (i32.const 0x461200) (i32.const 7))  (call $w_bstr (i32.const 0x440000) (i32.const 33))     ;; grantee = my idhash
    (call $w_text (i32.const 0x461240) (i32.const 7))  (call $w_bstr (i32.const 0x440000) (i32.const 33))     ;; granter = my idhash
    (call $w_text (i32.const 0x461280) (i32.const 10)) (call $w_uint (local.get $ms))                          ;; created_at
    (local.set $tdlen (i32.sub (global.get $g_wp) (i32.const 0x981000)))
    (drop (call $content_hash (i32.const 0x461540) (i32.const 23) (i32.const 0x981000) (local.get $tdlen) (i32.const 0x985080)))  ;; grant_ch
    (global.set $g_wp (i32.const 0x983000))
    (call $w_entity (i32.const 0x461540) (i32.const 23) (i32.const 0x981000) (local.get $tdlen) (i32.const 0x985080))  ;; system/capability/token
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x983000)))
    (global.set $g_wp (i32.const 0x980000))
    (call $w_bytes (i32.const 0x466860) (i32.const 25)) (call $w_bytes (global.get $g_patp) (global.get $g_patlen))  ;; system/capability/grants/{pattern}
    (local.set $gplen (i32.sub (global.get $g_wp) (i32.const 0x980000)))
    (call $store_put (i32.const 0x980000) (local.get $gplen) (i32.const 0x983000) (local.get $blen))
    ;; ===== WRITE 4: grant signature @ system/signature/{hex(grant_ch)} (§3.5 invariant ptr) =====
    (drop (call $ed_sign (i32.const 0x420000) (i32.const 0x985080) (i32.const 33) (i32.const 0x985200)))       ;; sign grant_ch
    (global.set $g_wp (i32.const 0x982000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x461100) (i32.const 6))  (call $w_bstr (i32.const 0x440000) (i32.const 33))      ;; signer = my idhash
    (call $w_text (i32.const 0x461140) (i32.const 6))  (call $w_bstr (i32.const 0x985080) (i32.const 33))      ;; target = grant_ch
    (call $w_text (i32.const 0x461180) (i32.const 9))  (call $w_text (i32.const 0x461600) (i32.const 7))       ;; algorithm:ed25519
    (call $w_text (i32.const 0x4610c0) (i32.const 9))  (call $w_bstr (i32.const 0x985200) (i32.const 64))      ;; signature
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x982000)))
    (drop (call $content_hash (i32.const 0x461500) (i32.const 16) (i32.const 0x982000) (local.get $dlen) (i32.const 0x9850c0)))  ;; sig_ch
    (global.set $g_wp (i32.const 0x983000))
    (call $w_entity (i32.const 0x461500) (i32.const 16) (i32.const 0x982000) (local.get $dlen) (i32.const 0x9850c0))  ;; system/signature
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x983000)))
    (call $hexenc (i32.const 0x985080) (i32.const 0x980100))                                                   ;; hex(grant_ch) → 66 chars
    (global.set $g_wp (i32.const 0x980200))
    (call $w_bytes (i32.const 0x466890) (i32.const 17)) (call $w_bytes (i32.const 0x980100) (i32.const 66))     ;; system/signature/{hex}
    (local.set $splen (i32.sub (global.get $g_wp) (i32.const 0x980200)))
    (call $store_put (i32.const 0x980200) (local.get $splen) (i32.const 0x983000) (local.get $blen))
    ;; ===== RESPONSE: 200 system/handler/register-result {grant:<token data>, pattern} =====
    (global.set $g_wp (i32.const 0x982000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x466930) (i32.const 5))  (call $w_bytes (i32.const 0x981000) (local.get $tdlen))  ;; grant = token data (verbatim)
    (call $w_text (i32.const 0x462580) (i32.const 7))  (call $w_text (global.get $g_patp) (global.get $g_patlen))  ;; pattern
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x982000)))
    (drop (call $content_hash (i32.const 0x466820) (i32.const 30) (i32.const 0x982000) (local.get $rdlen) (i32.const 0x985100)))
    (global.set $g_wp (i32.const 0x984000))
    (call $w_entity (i32.const 0x466820) (i32.const 30) (i32.const 0x982000) (local.get $rdlen) (i32.const 0x985100))  ;; register-result
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x984000)))
    (call $build_get_ok (local.get $out) (i32.const 0x984000) (local.get $blen) (local.get $rid) (local.get $rlen)))

  ;; §6.13a / §10.1 system/handler `unregister`: §5.2-authorize, then reverse the five writes —
  ;; remove interface @ system/handler/{pattern}, handler @ {pattern}, grant @
  ;; system/capability/grants/{pattern}, and its signature @ system/signature/{hex(grant_hash)}
  ;; (the grant hash read from the STORED grant entity so it matches the register-time hash — the
  ;; token's created_at makes a re-mint diverge). Empty-params (§3.2). Return 200.
  (func $serve_unregister (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $gplen i32) (local $grant i32) (local $chf i32) (local $chp i32) (local $splen i32)
    (local.set $e (call $chain_depth_check (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $reg_pattern (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    ;; interface @ system/handler/{pattern}; handler @ {pattern}
    (call $store_remove (global.get $g_rtp) (global.get $g_rtlen))
    (call $store_remove (global.get $g_patp) (global.get $g_patlen))
    ;; grant path @0x980000
    (global.set $g_wp (i32.const 0x980000))
    (call $w_bytes (i32.const 0x466860) (i32.const 25)) (call $w_bytes (global.get $g_patp) (global.get $g_patlen))
    (local.set $gplen (i32.sub (global.get $g_wp) (i32.const 0x980000)))
    ;; signature removal: read the stored grant's content_hash → invariant sig path → remove.
    (local.set $grant (call $store_get (i32.const 0x980000) (local.get $gplen)))
    (if (local.get $grant)
      (then
        (local.set $chf (call $map_find (local.get $grant) (i32.const 0x460030) (i32.const 12)))   ;; content_hash
        (if (i32.ne (local.get $chf) (i32.const -1))
          (then
            (local.set $chp (call $rd_head (local.get $chf)))
            (call $hexenc (local.get $chp) (i32.const 0x980100))
            (global.set $g_wp (i32.const 0x980200))
            (call $w_bytes (i32.const 0x466890) (i32.const 17)) (call $w_bytes (i32.const 0x980100) (i32.const 66))
            (local.set $splen (i32.sub (global.get $g_wp) (i32.const 0x980200)))
            (call $store_remove (i32.const 0x980200) (local.get $splen))))))
    (call $store_remove (i32.const 0x980000) (local.get $gplen))                                    ;; grant last
    (call $build_put_ok (local.get $out) (local.get $rid) (local.get $rlen)))

  ;; system/tree `put` (§6.3): §5.2-authorize (same prefix as get), then bind params.data.entity
  ;; at resource.targets[0] with §3.9 CAS via expected_hash (absent→unconditional; zero→create,
  ;; 409 if bound; non-zero→replace, 409 if unbound or current content_hash differs). entity
  ;; absent/null removes the binding. Reuses the persistent store + get-shaped 200 response.
  (func $serve_tree_put (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $res i32) (local $ta i32) (local $tp i32) (local $tlen i32)
    (local $params i32) (local $pdata i32) (local $ent i32) (local $entlen i32)
    (local $exp i32) (local $expp i32) (local $cur i32) (local $curch i32) (local $isdel i32)
    (local.set $e (call $chain_depth_check (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $res (call $map_find (local.get $edp) (i32.const 0x462080) (i32.const 8)))
    (if (i32.eq (local.get $res) (i32.const -1)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ta (call $map_find (local.get $res) (i32.const 0x4620c0) (i32.const 7)))
    (if (i32.eq (local.get $ta) (i32.const -1)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tp (call $rd_head (local.get $ta)))
    (if (i64.eqz (global.get $g_arg)) (then (return (call $err_404 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tp (call $rd_head (local.get $tp)))
    (local.set $tlen (i32.wrap_i64 (global.get $g_arg)))
    (if (i32.eqz (call $path_valid (local.get $tp) (local.get $tlen)))
      (then (return (call $build_error (local.get $out) (i32.const 0x4622c0) (i32.const 12) (i32.const 400) (local.get $rid) (local.get $rlen)))))
    (call $canon_path (local.get $tp) (local.get $tlen))   ;; §1.4 canonical store key
    (local.set $tp (global.get $g_cpp)) (local.set $tlen (global.get $g_cplen))
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ent (call $map_find (local.get $pdata) (i32.const 0x466700) (i32.const 6)))          ;; entity
    (local.set $exp (call $map_find (local.get $pdata) (i32.const 0x466720) (i32.const 13)))         ;; expected_hash
    (local.set $cur (call $store_get (local.get $tp) (local.get $tlen)))                             ;; 0 if unbound
    (if (i32.ne (local.get $exp) (i32.const -1))
      (then
        (local.set $expp (call $rd_head (local.get $exp)))
        (if (call $is_zero33 (local.get $expp))
          (then (if (local.get $cur) (then (return (call $err_409hm (local.get $out) (local.get $rid) (local.get $rlen))))))
          (else
            (if (i32.eqz (local.get $cur)) (then (return (call $err_409hm (local.get $out) (local.get $rid) (local.get $rlen)))))
            (local.set $curch (call $map_find (local.get $cur) (i32.const 0x460030) (i32.const 12)))
            (if (i32.eq (local.get $curch) (i32.const -1)) (then (return (call $err_409hm (local.get $out) (local.get $rid) (local.get $rlen)))))
            (if (call $mcmp33 (call $rd_head (local.get $curch)) (local.get $expp)) (then (return (call $err_409hm (local.get $out) (local.get $rid) (local.get $rlen)))))))))
    ;; entity absent (-1) OR present-and-null (0xf6) → delete. Compute with short-circuit so a
    ;; -1 pointer is never dereferenced (i32.or evaluates both operands eagerly).
    (local.set $isdel (i32.eq (local.get $ent) (i32.const -1)))
    (if (i32.eqz (local.get $isdel))
      (then (if (i32.eq (i32.load8_u (local.get $ent)) (i32.const 0xf6)) (then (local.set $isdel (i32.const 1))))))
    (if (result i32) (local.get $isdel)
      (then
        (call $store_remove (local.get $tp) (local.get $tlen))
        (call $build_put_ok (local.get $out) (local.get $rid) (local.get $rlen)))
      (else
        (local.set $entlen (i32.sub (call $skip (local.get $ent)) (local.get $ent)))
        (call $store_put (local.get $tp) (local.get $tlen) (local.get $ent) (local.get $entlen))
        (call $build_get_ok (local.get $out) (local.get $ent) (local.get $entlen) (local.get $rid) (local.get $rlen)))))

  ;; 400 invalid_params shorthand (capability write handlers).
  (func $err_invparams (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462b80) (i32.const 14) (i32.const 400) (local.get $rid) (local.get $rlen)))
  ;; 501 unsupported_operation shorthand.
  (func $err_501 (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (call $build_error (local.get $out) (i32.const 0x462a80) (i32.const 21) (i32.const 501) (local.get $rid) (local.get $rlen)))

  ;; system/capability `request` (§6.2): §5.2-authorize the caller (auth+cap; attenuation
  ;; bounds the grant, not the target-based scope gate), mint a token whose grants are copied
  ;; verbatim from params.data.grants (grantee = request author, granter = this peer), sign it,
  ;; return 200 system/capability/grant with {token, my peer, signature} in a sorted included.
  (func $build_request (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $author i32) (local $ap i32) (local $params i32) (local $pdata i32)
    (local $grants i32) (local $gptr i32) (local $glen i32)
    (local $cap i32) (local $capp i32) (local $incl i32) (local $tok i32) (local $ctd i32)
    (local $ms i64) (local $toklen i32) (local $sigdlen i32) (local $grlen i32) (local $rdlen i32) (local $peerlen i32)
    (local $f i32) (local $expv i64) (local $exp_have i32) (local $tterm i64)
    ;; §5.2 auth-class (401) then capability-class (403). No grant-scope gate — a request op
    ;; carries no resource.targets; attenuation below is the widening guard.
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_op_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    ;; grantee = request author (33); source stays valid in the request buffer through mint
    (local.set $author (call $map_find (local.get $edp) (i32.const 0x462000) (i32.const 6)))
    (if (i32.eq (local.get $author) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ap (call $rd_head (local.get $author)))
    ;; requested grants = params.data.grants (raw CBOR array) → gptr/glen
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $grants (call $map_find (local.get $pdata) (i32.const 0x4611c0) (i32.const 6)))
    (if (i32.eq (local.get $grants) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $gptr (local.get $grants))
    (local.set $glen (i32.sub (call $skip (local.get $grants)) (local.get $grants)))
    ;; attenuation (§6.2): resolve the caller's token data (data.capability → included) and
    ;; require every requested grant to be covered by some caller grant, else 403.
    (local.set $cap (call $map_find (local.get $edp) (i32.const 0x462040) (i32.const 10)))
    (if (i32.eq (local.get $cap) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $capp (call $rd_head (local.get $cap)))
    (local.set $incl (call $map_find (local.get $in) (i32.const 0x461040) (i32.const 8)))
    (if (i32.eq (local.get $incl) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tok (call $included_find_by_key (local.get $incl) (local.get $capp)))
    (if (i32.eqz (local.get $tok)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $ctd (call $map_find (local.get $tok) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $ctd) (i32.const -1)) (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    (if (i32.eqz (call $grants_attenuated (local.get $gptr) (local.get $ctd)))
      (then (return (call $err_capden (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; ======================= mint (mirror $build_auth's tail) =======================
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    ;; ---- §6.2 CAP-5 / §5.6 MIN_DEFINED mint ceiling ----
    ;;
    ;;   expires_at = MIN_DEFINED( caller_capability.expires_at,   ; ABSOLUTE, enters directly
    ;;                             created_at + request.ttl_ms )   ; DURATION, converted first
    ;;
    ;; `request` mints a ROOT token (parent: null), so §5.6's parent-child attenuation never
    ;; reaches it — without this clamp, temporal attenuation is the one dimension a requester
    ;; could escape, and policy withdrawal would have no bounded latency. Note this is NOT an
    ;; authorization decision: an over-long ttl_ms from a bounded caller MINTS the clamped
    ;; value and returns 200, and refusing it is non-conformant.
    ;;
    ;; The value is reached BY CONSTRUCTION, not by comparison. A `<= caller_exp` check
    ;; satisfies a strictly weaker test than the one being run — the oracle says so in its
    ;; own failure text — so there is deliberately no comparison against the caller's expiry
    ;; anywhere in here.
    ;;
    ;; §5.6's third term, `created_at + policy_entry.ttl_ms`, is structurally absent on this
    ;; peer: it writes policy entries (§6.2 configure) but never reads one back on the request
    ;; path, so there is no policy entry in scope to take a ttl from. That is a missing TERM,
    ;; not a missing rule — MIN_DEFINED over the terms that exist is exactly what it computes.
    ;; `created_at` is sampled ONCE, above, and the duration term is converted against that
    ;; same instant; sampling again here would emit a token whose stated birth and derived
    ;; expiry are different instants.
    (local.set $f (call $map_find (local.get $ctd) (i32.const 0x462180) (i32.const 10)))     ;; caller expires_at
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.eq (global.get $g_major) (i32.const 0))
              (then (local.set $expv (global.get $g_arg)) (local.set $exp_have (i32.const 1))))))
    (local.set $f (call $map_find (local.get $pdata) (i32.const 0x463ac0) (i32.const 6)))    ;; request ttl_ms
    (if (i32.ne (local.get $f) (i32.const -1))
      (then (drop (call $rd_head (local.get $f)))
            (if (i32.eq (global.get $g_major) (i32.const 0))
              (then
                (local.set $tterm (i64.add (local.get $ms) (global.get $g_arg)))
                ;; §5.6 rule 3: a term that does not fit is DROPPED — never wrapped, never
                ;; saturated. Saturation would manufacture expires_at == 2^64-1, a finite
                ;; bound no reader can tell from a deliberate one. ttl_ms == 0 is NOT special-
                ;; cased (rule 2): it falls out as created_at, which is what keeps "expire
                ;; immediately" from collapsing into the absent/"no bound" spelling.
                (if (i64.ge_u (local.get $tterm) (local.get $ms))
                  (then (if (i32.eqz (local.get $exp_have))
                          (then (local.set $expv (local.get $tterm)) (local.set $exp_have (i32.const 1)))
                          (else (if (i64.lt_u (local.get $tterm) (local.get $expv))
                                  (then (local.set $expv (local.get $tterm))))))))))))
    ;; token data {grants:<raw copy>, grantee, granter, created_at[, expires_at]} @0x940000.
    ;; Canonical key order is length-then-lex, so expires_at sorts AFTER created_at (same
    ;; length, c < e) and appends cleanly at the end.
    (global.set $g_wp (i32.const 0x940000))
    (call $w_map (i64.extend_i32_u (i32.add (i32.const 4) (local.get $exp_have))))
    (call $w_text (i32.const 0x4611c0) (i32.const 6))  (call $w_bytes (local.get $gptr) (local.get $glen))    ;; grants (verbatim)
    (call $w_text (i32.const 0x461200) (i32.const 7))  (call $w_bstr (local.get $ap) (i32.const 33))          ;; grantee = author
    (call $w_text (i32.const 0x461240) (i32.const 7))  (call $w_bstr (i32.const 0x440000) (i32.const 33))     ;; granter = my idhash
    (call $w_text (i32.const 0x461280) (i32.const 10)) (call $w_uint (local.get $ms))                         ;; created_at
    (if (local.get $exp_have)
      (then (call $w_text (i32.const 0x462180) (i32.const 10)) (call $w_uint (local.get $expv))))              ;; expires_at
    (local.set $toklen (i32.sub (global.get $g_wp) (i32.const 0x940000)))
    (drop (call $content_hash (i32.const 0x461540) (i32.const 23) (i32.const 0x940000) (local.get $toklen) (i32.const 0x920100)))
    (drop (call $ed_sign (i32.const 0x420000) (i32.const 0x920100) (i32.const 33) (i32.const 0x920200)))
    ;; signature entity data {signer,target,algorithm,signature} @0x960000
    (global.set $g_wp (i32.const 0x960000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x461100) (i32.const 6))  (call $w_bstr (i32.const 0x440000) (i32.const 33))     ;; signer = my idhash
    (call $w_text (i32.const 0x461140) (i32.const 6))  (call $w_bstr (i32.const 0x920100) (i32.const 33))     ;; target = tok_ch
    (call $w_text (i32.const 0x461180) (i32.const 9))  (call $w_text (i32.const 0x461600) (i32.const 7))      ;; algorithm:ed25519
    (call $w_text (i32.const 0x4610c0) (i32.const 9))  (call $w_bstr (i32.const 0x920200) (i32.const 64))     ;; signature
    (local.set $sigdlen (i32.sub (global.get $g_wp) (i32.const 0x960000)))
    (drop (call $content_hash (i32.const 0x461500) (i32.const 16) (i32.const 0x960000) (local.get $sigdlen) (i32.const 0x920180)))
    ;; grant result data {token: tok_ch} @0x958000
    (global.set $g_wp (i32.const 0x958000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x4612c0) (i32.const 5)) (call $w_bstr (i32.const 0x920100) (i32.const 33))       ;; token
    (local.set $grlen (i32.sub (global.get $g_wp) (i32.const 0x958000)))
    (drop (call $content_hash (i32.const 0x461580) (i32.const 23) (i32.const 0x958000) (local.get $grlen) (i32.const 0x920140)))
    ;; my peer entity data {key_type, public_key} @0x968000
    (local.set $peerlen (call $build_peer_data (i32.const 0x420100) (i32.const 0x968000)))
    ;; response data {result:<grant entity>, status:200, request_id} @0x959000
    (global.set $g_wp (i32.const 0x959000))
    (call $w_map (i64.const 3))
    (call $w_text (i32.const 0x460090) (i32.const 6))
    (call $w_entity (i32.const 0x461580) (i32.const 23) (i32.const 0x958000) (local.get $grlen) (i32.const 0x920140))
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (i64.const 200))
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (local.get $rid) (local.get $rlen))
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x959000)))
    (drop (call $content_hash (i32.const 0x460040) (i32.const 32) (i32.const 0x959000) (local.get $rdlen) (i32.const 0x9201c0)))
    ;; envelope {root:<resp entity>, included:{token, peer, sig} sorted} @out
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x460000) (i32.const 4))
    (call $w_entity (i32.const 0x460040) (i32.const 32) (i32.const 0x959000) (local.get $rdlen) (i32.const 0x9201c0))
    (call $w_text (i32.const 0x461040) (i32.const 8))
    (call $store_incl (i32.const 0) (i32.const 0x920100) (i32.const 0x461540) (i32.const 23) (i32.const 0x940000) (local.get $toklen) (i32.const 0x920100))
    (call $store_incl (i32.const 1) (i32.const 0x440000) (i32.const 0x4614c0) (i32.const 11) (i32.const 0x968000) (local.get $peerlen) (i32.const 0x440000))
    (call $store_incl (i32.const 2) (i32.const 0x920180) (i32.const 0x461500) (i32.const 16) (i32.const 0x960000) (local.get $sigdlen) (i32.const 0x920180))
    (call $emit_incl3)
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; system/capability `revoke` (§6.9a): auth+cap, then write a revocation marker at
  ;; system/capability/revocations/<hex(token)> (handler-set revoked_at) into the write store;
  ;; a later EXECUTE presenting that token is denied by the is_revoked gate in $verify_cap.
  (func $serve_revoke (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $params i32) (local $pdata i32) (local $tokv i32) (local $tp i32)
    (local $i i32) (local $acc i32) (local $reason i32) (local $rvlen i32) (local $ms i64)
    (local $dlen i32) (local $pathlen i32) (local $entlen i32) (local $nk i32)
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_op_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tokv (call $map_find (local.get $pdata) (i32.const 0x4612c0) (i32.const 5)))       ;; token
    (if (i32.eq (local.get $tokv) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tp (call $rd_head (local.get $tokv)))
    (if (i64.ne (global.get $g_arg) (i64.const 33)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; reject an all-zero token
    (local.set $acc (i32.const 0))
    (block $zd (loop $zl
      (br_if $zd (i32.ge_u (local.get $i) (i32.const 33)))
      (local.set $acc (i32.or (local.get $acc) (i32.load8_u (i32.add (local.get $tp) (local.get $i)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $zl)))
    (if (i32.eqz (local.get $acc)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (drop (call $clock_time_get (i32.const 0) (i64.const 0) (i32.const 0x930040)))
    (local.set $ms (i64.div_u (i64.load (i32.const 0x930040)) (i64.const 1000000)))
    ;; reason (raw value) if present
    (local.set $reason (call $map_find (local.get $pdata) (i32.const 0x464340) (i32.const 6)))     ;; reason
    (if (i32.ne (local.get $reason) (i32.const -1))
      (then (local.set $rvlen (i32.sub (call $skip (local.get $reason)) (local.get $reason))))
      (else (local.set $reason (i32.const 0))))
    ;; revocation data {token, [reason], revoked_at} @0x979000
    (local.set $nk (if (result i32) (local.get $reason) (then (i32.const 3)) (else (i32.const 2))))
    (global.set $g_wp (i32.const 0x979000))
    (call $w_map (i64.extend_i32_u (local.get $nk)))
    (call $w_text (i32.const 0x4612c0) (i32.const 5)) (call $w_bstr (local.get $tp) (i32.const 33))            ;; token
    (if (local.get $reason)
      (then (call $w_text (i32.const 0x464340) (i32.const 6)) (call $w_bytes (local.get $reason) (local.get $rvlen))))  ;; reason (verbatim)
    (call $w_text (i32.const 0x464380) (i32.const 10)) (call $w_uint (local.get $ms))                          ;; revoked_at
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x979000)))
    (drop (call $content_hash (i32.const 0x464300) (i32.const 28) (i32.const 0x979000) (local.get $dlen) (i32.const 0x920100)))
    ;; revocation entity @0x97A000
    (global.set $g_wp (i32.const 0x97A000))
    (call $w_entity (i32.const 0x464300) (i32.const 28) (i32.const 0x979000) (local.get $dlen) (i32.const 0x920100))
    (local.set $entlen (i32.sub (global.get $g_wp) (i32.const 0x97A000)))
    ;; store at revocations/<hex(token)>
    (local.set $pathlen (call $revoc_path (local.get $tp)))
    (call $store_put (i32.const 0x978000) (local.get $pathlen) (i32.const 0x97A000) (local.get $entlen))
    (call $build_get_ok (local.get $out) (i32.const 0x97A000) (local.get $entlen) (local.get $rid) (local.get $rlen)))

  ;; system/capability `configure` (§6.2): auth+cap (no scope — a configure carries no
  ;; resource.targets), reject a partial-prefix ('*') peer_pattern (400), write the params
  ;; policy-entry verbatim at system/capability/policy/<peer_pattern>, and echo it as 200.
  (func $serve_configure (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $params i32) (local $plen i32) (local $pdata i32) (local $pat i32)
    (local $patp i32) (local $patlen i32) (local $i i32) (local $pathlen i32)
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_op_scope (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $plen (i32.sub (call $skip (local.get $params)) (local.get $params)))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pat (call $map_find (local.get $pdata) (i32.const 0x464200) (i32.const 12)))       ;; peer_pattern
    (if (i32.ne (local.get $pat) (i32.const -1))
      (then
        (local.set $patp (call $rd_head (local.get $pat)))
        (local.set $patlen (i32.wrap_i64 (global.get $g_arg)))
        ;; §4 reject any '*' (partial-prefix) → 400 invalid_params
        (local.set $i (i32.const 0))
        (block $wd (loop $wl
          (br_if $wd (i32.ge_u (local.get $i) (local.get $patlen)))
          (if (i32.eq (i32.load8_u (i32.add (local.get $patp) (local.get $i))) (i32.const 0x2a))
            (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $wl)))
        ;; store the policy-entry at system/capability/policy/<peer_pattern>
        (global.set $g_wp (i32.const 0x978000))
        (call $w_bytes (i32.const 0x462ac0) (i32.const 25))
        (call $w_bytes (local.get $patp) (local.get $patlen))
        (local.set $pathlen (i32.sub (global.get $g_wp) (i32.const 0x978000)))
        (call $store_put (i32.const 0x978000) (local.get $pathlen) (local.get $params) (local.get $plen))))
    (call $build_get_ok (local.get $out) (local.get $params) (local.get $plen) (local.get $rid) (local.get $rlen)))

  ;; §7a.1 system/validate/echo:echo — return the params entity verbatim as the 200 result.
  (func $serve_echo (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $params i32) (local $plen i32)
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))   ;; params (inline entity)
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $plen (i32.sub (call $skip (local.get $params)) (local.get $params)))
    (call $build_get_ok (local.get $out) (local.get $params) (local.get $plen) (local.get $rid) (local.get $rlen)))

  ;; §7a.1 system/validate/dispatch-outbound:dispatch — the §6.11 reentrant outbound seam.
  ;; §5.2-authorize, parse params {target, value, reentry_capability/granter/cap_signature}, author
  ;; a FULL outbound echo EXECUTE (author-signed root + capability + included{author-sig, cap,
  ;; granter, cap-sig}) back down THIS connection, register (Ei→Di) in the pending table, and emit
  ;; the echo frame. The dispatch-outbound reply is deferred to serve_resume when the echo's
  ;; EXECUTE_RESPONSE returns (§7a.2a same-connection reentry). Scratch: root data 0x977000, sig
  ;; data 0x978000, Ei rid 0x979000; hashes params_ch 0x985300 / root_ch 0x985340 / authsig_ch
  ;; 0x985380 / sig64 0x985400; included table 0x973000.
  (func $serve_dispatch_outbound (param $in i32) (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $e i32) (local $params i32) (local $pdata i32)
    (local $tgt i32) (local $tgtl i32) (local $val i32) (local $vall i32)
    (local $rcap i32) (local $rgr i32) (local $rcs i32)
    (local $capch i32) (local $grch i32) (local $csch i32)
    (local $eil i32) (local $rdlen i32) (local $blen i32)
    ;; §5.2 ladder (matches serve_register): 401 no author / 403 no-or-invalid cap.
    (local.set $e (call $verify_auth (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    (local.set $e (call $verify_cap (local.get $edp) (local.get $in) (local.get $out) (local.get $rid) (local.get $rlen)))
    (if (local.get $e) (then (return (local.get $e))))
    ;; params.data
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; target (text) → outbound uri
    (local.set $tgt (call $map_find (local.get $pdata) (i32.const 0x466b60) (i32.const 6)))     ;; "target"
    (if (i32.eq (local.get $tgt) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $tgt (call $rd_head (local.get $tgt))) (local.set $tgtl (i32.wrap_i64 (global.get $g_arg)))
    ;; value (raw ecf {value:X} blob) — full encoded span, becomes outbound params entity DATA.
    (local.set $val (call $map_find (local.get $pdata) (i32.const 0x466b40) (i32.const 5)))      ;; "value"
    (if (i32.eq (local.get $val) (i32.const -1)) (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $vall (i32.sub (call $skip (local.get $val)) (local.get $val)))
    ;; the three in-band authority entities (nested {data,type,content_hash} maps).
    (local.set $rcap (call $map_find (local.get $pdata) (i32.const 0x466b80) (i32.const 18)))    ;; reentry_capability
    (local.set $rgr  (call $map_find (local.get $pdata) (i32.const 0x466bc0) (i32.const 15)))    ;; reentry_granter
    (local.set $rcs  (call $map_find (local.get $pdata) (i32.const 0x466c00) (i32.const 21)))    ;; reentry_cap_signature
    (if (i32.or (i32.eq (local.get $rcap) (i32.const -1)) (i32.or (i32.eq (local.get $rgr) (i32.const -1)) (i32.eq (local.get $rcs) (i32.const -1))))
      (then (return (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))))
    ;; content_hash (33B) of each authority entity → root.capability + included keys.
    (local.set $capch (call $rd_head (call $map_find (local.get $rcap) (i32.const 0x460030) (i32.const 12))))
    (local.set $grch  (call $rd_head (call $map_find (local.get $rgr)  (i32.const 0x460030) (i32.const 12))))
    (local.set $csch  (call $rd_head (call $map_find (local.get $rcs)  (i32.const 0x460030) (i32.const 12))))
    ;; fresh outbound request_id (Ei) → 0x979000
    (local.set $eil (call $w_ei_rid (i32.const 0x979000)))
    ;; ---- outbound EXECUTE root data {uri, author, params, operation, capability, request_id} @0x977000 ----
    (global.set $g_wp (i32.const 0x977000))
    (call $w_map (i64.const 6))
    (call $w_text (i32.const 0x462100) (i32.const 3))  (call $w_text (local.get $tgt) (local.get $tgtl))    ;; uri = target
    (call $w_text (i32.const 0x462000) (i32.const 6))  (call $w_bstr (i32.const 0x440000) (i32.const 33))   ;; author = my idhash
    (call $w_text (i32.const 0x461000) (i32.const 6))                                                        ;; params (inline primitive/any entity)
    (drop (call $content_hash (i32.const 0x462840) (i32.const 13) (local.get $val) (local.get $vall) (i32.const 0x985300)))
    (call $w_entity (i32.const 0x462840) (i32.const 13) (local.get $val) (local.get $vall) (i32.const 0x985300))
    (call $w_text (i32.const 0x4600c0) (i32.const 9))  (call $w_text (i32.const 0x466b20) (i32.const 4))     ;; operation = echo
    (call $w_text (i32.const 0x462040) (i32.const 10)) (call $w_bstr (local.get $capch) (i32.const 33))      ;; capability = cap_ch
    (call $w_text (i32.const 0x4600b0) (i32.const 10)) (call $w_text (i32.const 0x979000) (local.get $eil))  ;; request_id = Ei
    (local.set $rdlen (i32.sub (global.get $g_wp) (i32.const 0x977000)))
    (drop (call $content_hash (i32.const 0x465640) (i32.const 23) (i32.const 0x977000) (local.get $rdlen) (i32.const 0x985340)))  ;; root_ch
    ;; author signature over root_ch → sig entity {signer, target, algorithm, signature} @0x978000
    (drop (call $ed_sign (i32.const 0x420000) (i32.const 0x985340) (i32.const 33) (i32.const 0x985400)))
    (global.set $g_wp (i32.const 0x978000))
    (call $w_map (i64.const 4))
    (call $w_text (i32.const 0x461100) (i32.const 6))  (call $w_bstr (i32.const 0x440000) (i32.const 33))    ;; signer = my idhash
    (call $w_text (i32.const 0x461140) (i32.const 6))  (call $w_bstr (i32.const 0x985340) (i32.const 33))    ;; target = root_ch
    (call $w_text (i32.const 0x461180) (i32.const 9))  (call $w_text (i32.const 0x461600) (i32.const 7))     ;; algorithm:ed25519
    (call $w_text (i32.const 0x4610c0) (i32.const 9))  (call $w_bstr (i32.const 0x985400) (i32.const 64))    ;; signature
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x978000)))
    (drop (call $content_hash (i32.const 0x461500) (i32.const 16) (i32.const 0x978000) (local.get $blen) (i32.const 0x985380)))  ;; authsig_ch
    ;; ---- included: author-sig(built) + cap + granter + cap-sig (parsed, verbatim) ----
    (call $store_incl (i32.const 0) (i32.const 0x985380) (i32.const 0x461500) (i32.const 16) (i32.const 0x978000) (local.get $blen) (i32.const 0x985380))
    (call $store_incl_ent (i32.const 1) (local.get $rcap) (local.get $capch))
    (call $store_incl_ent (i32.const 2) (local.get $rgr)  (local.get $grch))
    (call $store_incl_ent (i32.const 3) (local.get $rcs)  (local.get $csch))
    ;; ---- envelope {root, included} @out ----
    (global.set $g_wp (local.get $out))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x460000) (i32.const 4))                                                        ;; root
    (call $w_entity (i32.const 0x465640) (i32.const 23) (i32.const 0x977000) (local.get $rdlen) (i32.const 0x985340))
    (call $w_text (i32.const 0x461040) (i32.const 8))                                                        ;; included
    (call $emit_incl_n (i32.const 4))
    ;; defer the dispatch-outbound reply: pending[Ei] = Di, emit the echo frame.
    (call $pend_add (i32.const 0x979000) (local.get $eil) (local.get $rid) (local.get $rlen))
    (i32.sub (global.get $g_wp) (local.get $out)))

  ;; §7a reentry completion: an inbound EXECUTE_RESPONSE on a --validate connection. If its
  ;; request_id matches a pending outbound echo (Ei), emit the deferred dispatch-outbound reply
  ;; {result:<primitive/any {result:<echo result entity>, status:<echo status>}>, status:200,
  ;; request_id:Di}; else drop (return -1 = send nothing). Scratch: inner data 0x977000, wrap
  ;; entity 0x978000, wrap hash 0x985340.
  (func $serve_resume (param $edp i32) (param $out i32) (result i32)
    (local $rid i32) (local $rlen i32) (local $ent i32) (local $er i32) (local $erl i32)
    (local $st i32) (local $stv i64) (local $dlen i32) (local $blen i32) (local $di i32) (local $dil i32)
    (local.set $rid (call $rd_head (call $map_find (local.get $edp) (i32.const 0x4600b0) (i32.const 10))))
    (local.set $rlen (i32.wrap_i64 (global.get $g_arg)))
    (local.set $ent (call $pend_take (local.get $rid) (local.get $rlen)))
    (if (i32.eqz (local.get $ent)) (then (return (i32.const -1))))          ;; stray/unmatched → drop
    (local.set $dil (i32.load (i32.add (local.get $ent) (i32.const 40))))
    (local.set $di  (i32.add (local.get $ent) (i32.const 44)))
    ;; echo result entity (verbatim span) + status from the incoming EXECUTE_RESPONSE data.
    (local.set $er (call $map_find (local.get $edp) (i32.const 0x460090) (i32.const 6)))    ;; result
    (if (i32.eq (local.get $er) (i32.const -1)) (then (return (i32.const -1))))
    (local.set $erl (i32.sub (call $skip (local.get $er)) (local.get $er)))
    (local.set $st (call $map_find (local.get $edp) (i32.const 0x4600a0) (i32.const 6)))    ;; status
    (local.set $stv (i64.const 200))
    (if (i32.ne (local.get $st) (i32.const -1))
      (then (drop (call $rd_head (local.get $st))) (local.set $stv (global.get $g_arg))))
    ;; inner data {result:<echo result entity verbatim>, status:<uint>} @0x977000
    (global.set $g_wp (i32.const 0x977000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x460090) (i32.const 6))  (call $w_bytes (local.get $er) (local.get $erl))   ;; result
    (call $w_text (i32.const 0x4600a0) (i32.const 6))  (call $w_uint (local.get $stv))                    ;; status
    (local.set $dlen (i32.sub (global.get $g_wp) (i32.const 0x977000)))
    (drop (call $content_hash (i32.const 0x462840) (i32.const 13) (i32.const 0x977000) (local.get $dlen) (i32.const 0x985340)))
    (global.set $g_wp (i32.const 0x978000))
    (call $w_entity (i32.const 0x462840) (i32.const 13) (i32.const 0x977000) (local.get $dlen) (i32.const 0x985340))
    (local.set $blen (i32.sub (global.get $g_wp) (i32.const 0x978000)))
    ;; wrap as the dispatch-outbound 200 reply (result = the primitive/any entity above).
    (call $build_get_ok (local.get $out) (i32.const 0x978000) (local.get $blen) (local.get $di) (local.get $dil)))

  ;; system/capability `delegate` (§2.6 F1): same-peer-only in v1. A delegate with a parent
  ;; field is unsupported (501); one lacking the required parent is malformed (400).
  (func $serve_delegate (param $edp i32) (param $out i32) (param $rid i32) (param $rlen i32) (result i32)
    (local $params i32) (local $pdata i32) (local $parent i32)
    (local.set $params (call $map_find (local.get $edp) (i32.const 0x461000) (i32.const 6)))
    (if (i32.eq (local.get $params) (i32.const -1)) (then (return (call $err_501 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $pdata (call $map_find (local.get $params) (i32.const 0x460010) (i32.const 4)))
    (if (i32.eq (local.get $pdata) (i32.const -1)) (then (return (call $err_501 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (local.set $parent (call $map_find (local.get $pdata) (i32.const 0x462140) (i32.const 6)))     ;; parent
    (if (i32.ne (local.get $parent) (i32.const -1)) (then (return (call $err_501 (local.get $out) (local.get $rid) (local.get $rlen)))))
    (call $err_invparams (local.get $out) (local.get $rid) (local.get $rlen)))

  ;; dispatch(in,in_len,out,sess) → out_len. Parses the envelope; routes hello; echoes otherwise.
  ;; $sess = per-connection session state (nonce + hello_done), passed by the host per connection.
  (func $dispatch (export "dispatch") (param $in i32) (param $in_len i32) (param $out i32) (param $sess i32) (result i32)
    (local $rootp i32) (local $edp i32) (local $ridvp i32) (local $rid i32) (local $rlen i32)
    (local $opvp i32) (local $op i32) (local $oplen i32) (local $nrej i32)
    (block $echo
      (local.set $rootp (call $map_find (local.get $in) (i32.const 0x460000) (i32.const 4)))   ;; "root"
      (br_if $echo (i32.eq (local.get $rootp) (i32.const -1)))
      (local.set $edp (call $map_find (local.get $rootp) (i32.const 0x460010) (i32.const 4)))   ;; "data"
      (br_if $echo (i32.eq (local.get $edp) (i32.const -1)))
      ;; §7a: on a --validate connection an inbound EXECUTE_RESPONSE (root.type = execute/response,
      ;; no `operation`) is a reentry echo reply → complete the deferred dispatch-outbound. Must run
      ;; before the operation check below (which would otherwise fall through to the raw-echo path).
      (if (global.get $g_validate)
        (then
          (local.set $opvp (call $map_find (local.get $rootp) (i32.const 0x460020) (i32.const 4)))  ;; root "type"
          (if (i32.ne (local.get $opvp) (i32.const -1))
            (then
              (local.set $op (call $rd_head (local.get $opvp)))
              (if (call $streq (local.get $op) (i32.wrap_i64 (global.get $g_arg)) (i32.const 0x460040) (i32.const 32))  ;; system/protocol/execute/response
                (then (return (call $serve_resume (local.get $edp) (local.get $out)))))))))
      (local.set $ridvp (call $map_find (local.get $edp) (i32.const 0x4600b0) (i32.const 10)))  ;; "request_id"
      (br_if $echo (i32.eq (local.get $ridvp) (i32.const -1)))
      (local.set $rid (call $rd_head (local.get $ridvp)))
      (local.set $rlen (i32.wrap_i64 (global.get $g_arg)))
      (local.set $opvp (call $map_find (local.get $edp) (i32.const 0x4600c0) (i32.const 9)))    ;; "operation"
      (br_if $echo (i32.eq (local.get $opvp) (i32.const -1)))
      (local.set $op (call $rd_head (local.get $opvp)))
      (local.set $oplen (i32.wrap_i64 (global.get $g_arg)))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x4600d0) (i32.const 5))   ;; "hello"
        (then
          (local.set $nrej (call $hello_neg (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))
          (if (local.get $nrej) (then (return (local.get $nrej))))                              ;; §4.5 disjoint reject
          (return (call $build_hello (local.get $out) (local.get $rid) (local.get $rlen) (local.get $sess)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x4618c0) (i32.const 12))  ;; "authenticate"
        (then (return (call $build_auth (local.get $in) (local.get $out) (local.get $edp) (local.get $rid) (local.get $rlen) (local.get $sess)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x462200) (i32.const 3))   ;; "get" (system/tree)
        (then (return (call $serve_tree_get (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x462780) (i32.const 3))   ;; "put" (system/tree)
        (then (return (call $serve_tree_put (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x466940) (i32.const 8))   ;; "register" (system/handler)
        (then (return (call $serve_register (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x466960) (i32.const 10))  ;; "unregister" (system/handler)
        (then (return (call $serve_unregister (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x461780) (i32.const 7))   ;; "request" (system/capability)
        (then (return (call $build_request (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x462800) (i32.const 6))   ;; "revoke"
        (then (return (call $serve_revoke (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x462b40) (i32.const 9))   ;; "configure"
        (then (return (call $serve_configure (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (call $streq (local.get $op) (local.get $oplen) (i32.const 0x4627c0) (i32.const 8))   ;; "delegate"
        (then (return (call $serve_delegate (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; §7a --validate handlers: system/validate/dispatch-outbound:dispatch (reentrant outbound
      ;; seam) + system/validate/echo:echo. Op-gated (no other core handler uses these op names).
      (if (i32.and (global.get $g_validate) (call $streq (local.get $op) (local.get $oplen) (i32.const 0x466b00) (i32.const 8)))   ;; "dispatch"
        (then (return (call $serve_dispatch_outbound (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      (if (i32.and (global.get $g_validate) (call $streq (local.get $op) (local.get $oplen) (i32.const 0x466b20) (i32.const 4)))   ;; "echo"
        (then (return (call $serve_echo (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen)))))
      ;; any other EXECUTE → §6.5 resolution-first flow (401 auth / 404 handler / 501 unknown-op /
      ;; 403 scope / 501 unimplemented). The dedicated capability handler replaces the tail next.
      (return (call $serve_auth_op (local.get $in) (local.get $edp) (local.get $out) (local.get $rid) (local.get $rlen) (local.get $op) (local.get $oplen))))
    ;; fallthrough: envelope not a parseable EXECUTE → echo raw (last-resort, no request_id known)
    (global.set $g_wp (local.get $out))
    (call $w_bytes (local.get $in) (local.get $in_len))
    (local.get $in_len))
)
