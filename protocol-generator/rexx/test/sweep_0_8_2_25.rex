/* entity-core-protocol-rexx — 0.8.2.25 sweep unit gate (offline, no network).
 *
 * Pins the six pieces the 0.8.2.20 -> .25 arc landed on this peer, at the UNIT level.
 * The wire-level half -- "a pre-admission refusal reaches the socket" -- cannot be asked
 * here and is driven by output/scratch/preadm411.c against the peer's own run-s4.sh
 * launch; what this file pins is the MAPPING ("the code belongs to the cause") plus the
 * §3.3 ladder, §6.3's path check, the §5.4 sentinel's scoping and §5.5a's scope typing.
 *
 * THE FRAMING ARMS ARE NOT REACHABLE FROM HERE AT ALL, and that is a property of this
 * peer rather than of this file: the §1.6 de-framing lives in the ecnet C co-process, so
 * an over-limit length prefix and a mid-frame EOF are events the Rexx layer only ever
 * SEES, never DETECTS. What is unit-testable is the classification they arrive at and the
 * refusal built from it; the detection itself is driven over a socket.
 *
 * EVERY PREDICATE CASE CARRIES AN ACCEPT ASSERTION. A deny-only test of an authorization
 * predicate is indistinguishable from one asserting False == False, and the accept case is
 * what validates the FIXTURE: a grant fixture built the wrong way parses empty, the
 * predicate then denies everything, and every deny case passes for free.
 *
 * Usage: rexx <combined> <eccrypto-helper-path>
 */
parse arg eccrypto
numeric digits 200
signal on syntax name Fatal
call Ec_Init
call Crypto_Init eccrypto
EC.!PASS = 0; EC.!FAIL = 0

LP = '2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg'   /* a syntactically valid peer_id */

/* ══════════ §3.3 / §5.2 effective_targets (0.8.2.20/.21, N11) ══════════ */
say '-- effective_targets (3.3/5.2) --'

/* THE NON-LOSSY PROJECTION [MUST] (0.8.2.25 N11) -- and on THIS substrate the pair is not
   merely tidier, it is the only way to have the discriminator at all: a packed list with
   no items and an absent value are BYTE-IDENTICAL here (both ''), so a routine returning
   only the survivors could not tell its caller which empty it meant. */
call Check 'absent resource -> had_resource 0', \Eff_Had(Cap_EffectiveTargets(LP, MkExec('NORESOURCE', '')))
call Check 'present resource -> had_resource 1 (even when every target drops)', Eff_Had(Cap_EffectiveTargets(LP, MkExec('app/a', 'app/a')))
call Check 'self-excluded request -> empty survivor list', (Lst_Count(Eff_List(Cap_EffectiveTargets(LP, MkExec('app/a', 'app/a')))) == 0)
call Check 'the two empties are DISTINGUISHABLE', ,
  (Eff_Had(Cap_EffectiveTargets(LP, MkExec('NORESOURCE', ''))) \== Eff_Had(Cap_EffectiveTargets(LP, MkExec('app/a', 'app/a'))))

/* Survivors in the caller's OWN SPELLING (0.8.2.21), not canonicalized -- the value flows
   on to the store lookup, which canonicalizes for itself. */
e2 = Eff_List(Cap_EffectiveTargets(LP, MkExec('app/a app/b', 'app/b')))
call Check 'survivor keeps the caller''s raw spelling', (Lst_Item(e2, 1) == 'app/a')
call Check 'the non-excluded target survives, the excluded one does not', (Lst_Count(e2) == 1)
call Check 'a wildcard caller exclude carves out its whole subtree', (Lst_Count(Eff_List(Cap_EffectiveTargets(LP, MkExec('app/a app/b', 'app/*')))) == 0)

/* THE CALLER-EXCLUDE ARM IS FAIL-OPEN on an unmatchable pattern -- §5.4 rules it
   separately from the GRANT arm, which is fail-CLOSED (see the sentinel block below). The
   asymmetry is 0.8.2.21's whole point and it is INHERITED here rather than restated:
   Cap_Canonicalize answers the sentinel, Cap_MatchesPattern then answers 0, and the target
   simply survives. */
e3 = Eff_List(Cap_EffectiveTargets(LP, MkExec('app/a', '../nope')))
call Check 'unmatchable caller exclude carves out NOTHING (fail-open)', (Lst_Count(e3) == 1 & Lst_Item(e3, 1) == 'app/a')

/* ══════════ §6.3 check_path_permission (0.8.2.20/.22/.23) ══════════ */
say '-- check_path_permission (6.3) --'
tok = MkToken('system/tree', '', 'get', '', 'app/*', '')
p_ok   = '/' || LP || '/app/a'
p_deny = '/' || LP || '/other/a'

/* THE ACCEPT CASE IS THE FIXTURE VALIDATOR. Without it every deny below passes against a
   grant that parsed empty. */
call Check 'ACCEPT: all three dimensions match', Cap_CheckPathPermission(LP, 'get', p_ok, tok, 'system/tree')
/* One deny per DIMENSION: a single deny cannot distinguish "the predicate checks the
   dimension I care about" from "the predicate denies". */
call Check 'DENY on the resources dimension', \Cap_CheckPathPermission(LP, 'get', p_deny, tok, 'system/tree')
call Check 'DENY on the operations dimension (id-scope)', \Cap_CheckPathPermission(LP, 'put', p_ok, tok, 'system/tree')
call Check 'DENY on the handlers dimension', \Cap_CheckPathPermission(LP, 'get', p_ok, tok, 'system/other')

/* An empty resources.include is a LEGAL grant shape (§5.2: handlers that touch no tree
   paths) and DENIES every path here. */
call Check 'empty resources.include denies every path', \Cap_CheckPathPermission(LP, 'get', p_ok, MkToken('system/tree', '', 'get', '', '', ''), 'system/tree')
/* A malformed path canonicalizes to Cap_NeverMatch, which matches no grant, so it falls
   through to DENY rather than being matched against anything. */
call Check 'malformed path falls through to DENY, not to a throw', \Cap_CheckPathPermission(LP, 'get', '../escape', MkToken('system/tree', '', 'get', '', '*', ''), 'system/tree')
/* THREE DIMENSIONS, NOT FOUR: `peers` is not consulted (the path is local by construction
   here; §6.3's signature names only handlers, operations and resources). A grant whose
   `peers` dimension names a DIFFERENT peer still authorizes the path. */
gp = Cap_Grant(_pl('system/tree'), _pl('app/*'), _pl('get'), _pl('someotherpeer'))
tokp = Ent_Make('system/capability/token', Ecf_Map('grants', Ecf_Array(Lst_Add('', gp))))
call Check 'the `peers` dimension is NOT consulted (three dimensions, not four)', Cap_CheckPathPermission(LP, 'get', p_ok, tokp, 'system/tree')

/* ══════════ §5.4 sentinel scoped to PATH-SCOPE (0.8.2.24, N2/N3) — RULE B ══════════ */
say '-- 5.4 sentinel is path-scope only (0.8.2.24) --'
/* The symptom of the UN-scoped form: an `operations` exclude that PATH-canonicalizes to
   the sentinel -- an ordinary namespaced operation name -- denied the WHOLE dimension.
   Over-denial, invisible on any well-formed grant. */
call Check 'id-scope: a star-slash operations exclude does NOT deny the dimension', Cap_MatchesScope(LP, 'get', Scope_Make(_pl('*'), _pl('*/apply')), 'id')
call Check 'id-scope ACCEPT control: no exclude at all', Cap_MatchesScope(LP, 'get', Scope_Make(_pl('*'), ''), 'id')
call Check 'id-scope still EXCLUDES a literal that matches', \Cap_MatchesScope(LP, 'get', Scope_Make(_pl('*'), _pl('get')), 'id')
/* path-scope keeps the fail-CLOSED reading: an unmatchable GRANT exclude excludes
   everything (0.8.2.21). */
call Check 'path-scope: an unmatchable exclude still denies the dimension', \Cap_MatchesScope(LP, 'app/a', Scope_Make(_pl('*'), _pl('../nope')), 'path')
call Check 'path-scope ACCEPT control: a matchable exclude that misses', Cap_MatchesScope(LP, 'app/a', Scope_Make(_pl('*'), _pl('other/*')), 'path')

/* ══════════ §5.5a scope_subset typed by scope kind (F50, 0.8.2.16) — RULE E ══════════ */
say '-- 5.5a scope_subset is typed (F50 / 0.8.2.16) --'
/* entity-core-formalization's K-7 differential: 2 of 64 include pairs and 2 of 64 exclude
   pairs disagree between the literal and the canonicalizing readings, fail-closed, with a
   16-pair control alphabet reporting 0 -- which is why every hand-tried example missed it.
   Both witnesses are reproduced here, on the ID arm where the literal matcher binds. */
call Check 'id-scope subset: child /tree/get is inside parent *', Sub('*', '*', '/tree/get', '*', '*', '*')
/* The divergence: under the CANONICALIZING reading a child operations include of
   the star-slash-apply form canonicalizes to the sentinel, Cap_MatchesPattern then
   answers 0 in EITHER
   operand, and the subset check REFUSES a child that is plainly inside `*`. Under the
   literal matcher the parent's bare `*` covers it, which is what §3.6 requires. */
call Check 'id-scope subset: star-slash-apply is inside parent * (the K-7 witness)', Sub('*', '*', '*/apply', '*', '*', '*')
/* DENY control on the same arm, so the two above are not "subset always answers yes". */
call Check 'id-scope subset DENY: a child operation outside the parent include', \Sub('*', '*', 'put', '*', '*', 'get')

/* THE TYPING HAS TWO HALVES AND THE WITNESSES ABOVE ONLY MEASURE ONE. Found by planting on
   the sibling `tcl` peer: forcing the MATCHER to the path flavour while leaving the FRAME
   on id left every case above green, because for the star-slash-apply form vs a bare
   star the two matchers AGREE
   (both take the bare-star arm) and the whole divergence comes from CANONICALIZATION
   manufacturing the sentinel. So a pair is needed whose canonical forms are identical and
   whose MATCHERS disagree: the peer-wildcard form (slash star slash get) is a §5.4
   PATTERN under the path matcher and an ordinary literal under the id matcher, and
   Cap_Canonicalize is the identity on
   both operands (each already starts with '/'). §3.6: "An implementation on the
   canonicalizing reading is non-conformant and MUST adopt the literal matcher." */
call Check 'id-scope subset MATCHER arm: /a/get is NOT literally inside /*/get', \Sub('*', '*', '/a/get', '*', '*', '/*/get')
call Check 'path-scope subset MATCHER arm: /a/get IS inside the pattern /*/get', Sub('/a/get', '*', '*', '/*/get', '*', '*')

/* The PATH arm keeps the canonicalizing reading -- handlers and resources are path-scope. */
call Check 'path-scope subset: child app/a is inside parent app/*', Sub('*', 'app/a', '*', '*', 'app/*', '*')
call Check 'path-scope subset DENY: child outside the parent resource include', \Sub('*', 'other/a', '*', '*', 'app/*', '*')

/* ══════════ §4.11 / §5.2a — the code belongs to the CAUSE — RULES C/D ══════════ */
say '-- 4.11 pre-admission: the code belongs to the cause --'
call Check 'over-limit prefix -> 413 payload_too_large', (Sc('payload_too_large') == '413 payload_too_large')
/* A mis-keyed `included` entry carries NO TAG: its encoding is canonical, what is false is
   the claim the KEY makes, and the remedy non_canonical_ecf selects (*re-encode*) sends an
   honest caller to the wrong layer. §5.2a rules that code "NOT conformant here [MUST]". */
call Check 'mis-keyed included entry -> 400 hash_mismatch, NOT non_canonical_ecf', (Sc('included_key_mismatch') == '400 hash_mismatch')
call Check 'carried content_hash mismatch -> 400 hash_mismatch', (Sc('content_hash_mismatch') == '400 hash_mismatch')
/* The tag arm KEEPS non_canonical_ecf: ENTITY-CBOR-ENCODING defines that code for CBOR
   tag-policy violations specifically and still MUSTs it at decode time. Disjoint by CAUSE
   rather than in conflict. */
call Check 'a CBOR tag in a data field KEEPS 400 non_canonical_ecf', (Sc('TAG_REJECTED') == '400 non_canonical_ecf')
/* Everything else that never becomes an Envelope is the framing arm, on which
   non_canonical_ecf is explicitly NOT conformant. */
call Check 'non-minimal head -> 400 invalid_request (framing arm)', (Sc('NON_CANONICAL_ECF') == '400 invalid_request')
call Check 'truncated frame -> 400 invalid_request', (Sc('truncated_frame') == '400 invalid_request')
call Check 'a non-EXECUTE root -> 400 invalid_request', (Sc('non_execute_root') == '400 invalid_request')
call Check 'an unrecognised cause falls through to the framing arm', (Sc('not_a_map') == '400 invalid_request')
/* THE DIFFERENTIAL: the tag arm and the framing arm must answer DIFFERENT codes, or the
   peer is not classifying, it is just refusing. */
call Check 'the tag arm and the framing arm are DISTINGUISHED', (Sc('TAG_REJECTED') \== Sc('NON_CANONICAL_ECF'))
/* Every wire-visible message stays ASCII -- two peers in this cohort have been killed at
   runtime by a non-ASCII byte in an encoded string, on two unrelated compilers. */
call Check 'refusal messages are ASCII-only', (AsciiOnly(Msg('payload_too_large')) & AsciiOnly(Msg('included_key_mismatch')) & AsciiOnly(Msg('TAG_REJECTED')) & AsciiOnly(Msg('truncated_frame')))

/* ══════════ §3.3 ladder + §6.3 in the tree handler ══════════ */
say '-- 3.3 ladder + 6.3 in the tree handler --'
peer = Peer_Create(copies('37'x, 32), 0, 0)
LP2 = Peer_LocalPeer(peer)

/* RULE G -- OPERATION RESOLUTION PRECEDES RESOURCE VALIDATION. The defect this pins is an
   op ladder whose *any-operation, no-resource* arm matches BEFORE the unknown-operation
   arm, so `system/tree:bogusop` with no resource answers a RESOURCE error for an OPERATION
   fault. The differential is the point: the SAME unknown operation must answer 501 with a
   resource AND without one, or the resource ladder is reachable for an unknown op. */
call Check 'RULE G: unknown op WITHOUT a resource -> 501', (TStatus(peer, 'bogusop', 'NORESOURCE', '', '') == 501)
call Check 'RULE G: unknown op WITH a resource -> 501 (the differential)', (TStatus(peer, 'bogusop', 'app/a', '', '') == 501)
call Check 'RULE G: and it is the OPERATION code, not a resource code', (TCode(peer, 'bogusop', 'NORESOURCE', '', '') == 'unsupported_operation')
/* The companion control, so "501 to everything" cannot satisfy the above vacuously: a
   KNOWN op must still route into the ladder. */
call Check 'RULE G control: a KNOWN op still routes (not 501)', (TStatus(peer, 'get', 'NORESOURCE', '', '') \== 501)

/* The §3.3 ladder on `get` -- resource-OPTIONAL, BROAD-RESULT (EXTENSION-TREE §2.2a). */
call Check 'get, absent resource -> the root listing at 200', (TStatus(peer, 'get', 'NORESOURCE', '', '') == 200)
call Check 'get, PRESENT resource whose every target is self-excluded -> 400 path_required', (TCode(peer, 'get', 'app/a', 'app/a', '') == 'path_required')
call Check 'get, two surviving targets -> 400 ambiguous_resource', (TCode(peer, 'get', 'app/a app/b', '', '') == 'ambiguous_resource')
/* THE SELECTION MUST COME FROM THE EFFECTIVE SET, NOT targets[0] (0.8.2.20). With app/a
   excluded the survivor is app/b, so the handler must look for app/b -- a peer indexing
   targets[0] reports on app/a instead. */
call Check 'get selects from the EFFECTIVE set, never targets[0]', (TMsg(peer, 'get', 'app/a app/b', 'app/a', '') == '/' || LP2 || '/app/b')
call Check 'get, a PATTERN target -> 400 malformed_resource', (TCode(peer, 'get', 'app/*', '', '') == 'malformed_resource')
call Check 'get, a trailing slash is a LISTING request, not a pattern', (TStatus(peer, 'get', 'system/', '', '') == 200)

/* The §3.3 ladder on `put` -- resource-REQUIRED, so BOTH empties answer path_required.
   0.8.2.20 names answering `ambiguous_resource` for an absent resource as the exact
   inversion it forbids: *supply a resource* is not *disambiguate your request*. */
call Check 'put, absent resource -> 400 path_required (NOT ambiguous_resource)', (TCode(peer, 'put', 'NORESOURCE', '', '') == 'path_required')
call Check 'put, self-excluded resource -> 400 path_required', (TCode(peer, 'put', 'app/a', 'app/a', '') == 'path_required')
call Check 'put, two surviving targets -> 400 ambiguous_resource', (TCode(peer, 'put', 'app/a app/b', '', '') == 'ambiguous_resource')
call Check 'put, a PATTERN target -> 400 malformed_resource', (TCode(peer, 'put', 'app/*', '', '') == 'malformed_resource')

/* §6.3's path check AT THE HANDLER. The caller's own exclude vacates the dispatch-level
   check, so this is the only thing standing between the caller and the path. */
cap_ok = MkToken('*', '', '*', '', 'app/*', '')
call Check '6.3 ACCEPT: a covered path is not refused by the path check', (TStatus(peer, 'get', 'app/a', '', cap_ok) \== 403)
call Check '6.3 DENY: an UNCOVERED path -> 403 capability_denied', (TCode(peer, 'get', 'other/a', '', cap_ok) == 'capability_denied')
call Check '6.3 DENY on put as well as get', (TCode(peer, 'put', 'other/a', '', cap_ok) == 'capability_denied')
/* An unauthenticated / internal context has no caller to narrow and is NOT filtered. */
call Check 'no caller capability -> the path check does not fire', (TStatus(peer, 'get', 'other/a', '', '') == 404)

/* ══════════ §6.3 listing filter (0.8.2.21/.22) ══════════ */
say '-- 6.3 listing filter (0.8.2.21/.22) --'
store = Peer_Store(peer)
call Store_Bind store, '/' || LP2 || '/lst/qA', Ent_Make('primitive/string', Ecf_Str('qA'))
call Store_Bind store, '/' || LP2 || '/lst/qB', Ent_Make('primitive/string', Ecf_Str('qB'))
call Store_Bind store, '/' || LP2 || '/lst/qC', Ent_Make('primitive/string', Ecf_Str('qC'))
/* THE UNFILTERED CONTROL, and it is what makes the filtered case falsifiable: if the
   directory get does not work at all, "qB absent" is the trivial truth and measures
   nothing. */
all = Listing(peer, '', '')
call Check 'listing control: all three entries visible with no caller capability', (all == 'qA qB qC|3')
cap_x = MkToken('*', '', '*', '', 'lst/*', 'lst/qB')
filt = Listing(peer, '', cap_x)
call Check 'listing filter: an entry the caller''s own capability EXCLUDES is omitted', (word(translate(filt, ' ', '|'), 1) 'x' == 'qA' 'x' & pos('qB', filt) == 0)
/* `count` FOLLOWING THE SOURCE TOTAL IS THE DISCLOSURE BY ITSELF -- it tells the caller
   how many bindings exist under a prefix its capability does not cover. */
call Check 'listing filter: `count` reflects the FILTERED total, not the source tree''s', (filt == 'qA qC|2')
/* An include-narrowing filter, not only an exclude: the same rule has to hold when the
   grant simply does not reach the sibling. */
call Check 'listing filter: narrowing the INCLUDE omits the uncovered entries too', (Listing(peer, '', MkToken('*', '', '*', '', 'lst/qA', '')) == 'qA|1')
/*
 * NOT DRIVEN, and recorded rather than asserted with a case that would pass either way:
 * §6.3's "the DIRECTORY itself is deliberately not checked". Through this handler a grant
 * covering only `lst/qA` still yields a listing OF `lst/` (the case directly above proves
 * the filter runs, not that the prefix is unchecked), and a grant covering `lst/` cannot
 * distinguish a prefix-checking filter from a correct one. Separating the two needs a
 * caller whose grant covers children but NOT the node above them AND a dispatch chain that
 * lets the request reach the handler -- and §5.2 refuses that request one layer earlier.
 * The case above (`lst/qA` only) is the closest observable approximation: it reaches the
 * handler because this test drives the handler directly, and a prefix-checking filter
 * would answer an EMPTY listing there rather than qA. That is evidence, not a proof.
 */

say ''
say '=== sweep 0.8.2.25:' EC.!PASS 'pass /' EC.!FAIL 'fail ==='
/* ASSERT THE COUNT, not merely that the failure list is empty: a gate that examined zero
   things prints the same word as one that examined every case. */
if EC.!PASS + EC.!FAIL < 59 then do
  say 'FAIL: only' (EC.!PASS + EC.!FAIL) 'cases executed; the suite lost cases'
  exit 1
end
if EC.!FAIL > 0 then exit 1
exit 0

Fatal:
  say 'FATAL SYNTAX rc='rc' line='sigl' ('errortext(rc)')'
  say '  ->' condition('D')
  exit 3

Check: procedure expose EC.
  parse arg name, cond
  if cond then do; EC.!PASS = EC.!PASS + 1; say '  [PASS]' name; end
  else do; EC.!FAIL = EC.!FAIL + 1; say '  [FAIL]' name; end
  return

/* _pl -- a packed list from space-separated words ('' -> the empty list). */
_pl: procedure
  parse arg words
  l = ''
  do i = 1 to words(words)
    l = Lst_Add(l, word(words, i))
  end
  return l

/* MkExec -- an EXECUTE carrying an explicit `resource` map. `targets`/`excl` are
   space-separated; the sentinel 'NORESOURCE' omits the whole `resource` field, which is
   the input §3.3 makes DIFFERENT from a present resource whose targets all drop out. */
MkExec: procedure expose EC.
  parse arg targets, excl
  res = ''
  if targets \== 'NORESOURCE' then do
    res = Ecf_Map('targets', Ecf_TextArray(_pl(targets)))
    if excl \== '' then res = Ecf_MapPut(res, 'exclude', Ecf_TextArray(_pl(excl)))
  end
  return Wire_MakeExecute('r1', 'system/tree', 'get', Wire_EmptyParams(), '', '', res)

/* MkToken -- a capability token carrying ONE grant, each dimension as include/exclude. */
MkToken: procedure expose EC.
  parse arg hi, hx, oi, ox, ri, rx
  g = Ecf_Map('handlers', Ecf_Map('include', Ecf_TextArray(_pl(hi)), 'exclude', Ecf_TextArray(_pl(hx))))
  g = Ecf_MapPut(g, 'operations', Ecf_Map('include', Ecf_TextArray(_pl(oi)), 'exclude', Ecf_TextArray(_pl(ox))))
  g = Ecf_MapPut(g, 'resources', Ecf_Map('include', Ecf_TextArray(_pl(ri)), 'exclude', Ecf_TextArray(_pl(rx))))
  return Ent_Make('system/capability/token', Ecf_Map('grants', Ecf_Array(Lst_Add('', g))))

/* Sub -- Cap_GrantSubset over two single-grant shapes, local frames on both sides. */
Sub: procedure expose EC.
  parse arg ch, cr, co, ph, pr, po
  c = Cap_ParseGrant(Cap_Grant(_pl(ch), _pl(cr), _pl(co), ''))
  p = Cap_ParseGrant(Cap_Grant(_pl(ph), _pl(pr), _pl(po), ''))
  return Cap_GrantSubset('LOCALPEER', 'LOCALPEER', 'LOCALPEER', c, p)

/* Sc / Msg -- the status+code and the message of a §4.11 refusal classification. */
Sc: procedure expose EC.
  parse arg kind
  parse value Wire_PreAdmissionRefusal(kind) with st cd rest
  return st cd
Msg: procedure expose EC.
  parse arg kind
  parse value Wire_PreAdmissionRefusal(kind) with st cd rest
  return rest

AsciiOnly: procedure
  parse arg s
  do i = 1 to length(s)
    c = c2d(substr(s, i, 1))
    if c < 32 | c > 126 then return 0
  end
  return 1

/* TOut -- drive Hnd_Tree directly with a ctx carrying `cap` as the caller capability. */
TOut: procedure expose EC.
  parse arg peer, op, targets, excl, cap
  exec = MkExec(targets, excl)
  ctx = Ctx_Make(Conn_New(), cap, Env_Make(exec, ''), '/' || Peer_LocalPeer(peer) || '/system/tree')
  return Hnd_Tree(peer, op, ctx)
TStatus: procedure expose EC.
  parse arg peer, op, targets, excl, cap
  return Out_Status(TOut(peer, op, targets, excl, cap))
TCode: procedure expose EC.
  parse arg peer, op, targets, excl, cap
  return Ent_Text(Out_Result(TOut(peer, op, targets, excl, cap)), 'code')
TMsg: procedure expose EC.
  parse arg peer, op, targets, excl, cap
  return Ent_Text(Out_Result(TOut(peer, op, targets, excl, cap)), 'message')

/* Listing -- "seg seg seg|count" for a `lst/` directory get under `cap`. */
Listing: procedure expose EC.
  parse arg peer, unused, cap
  out = TOut(peer, 'get', 'lst/', '', cap)
  d = Ent_DataMap(Out_Result(out))
  em = Ecf_MapField(d, 'entries')
  names = ''
  do i = 1 to Ecf_MapCount(em)
    names = names Tv_Payload(Ecf_MapKey(em, i))
  end
  return strip(names) || '|' || Ecf_Uint(d, 'count')
