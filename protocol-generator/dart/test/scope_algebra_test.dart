import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:test/test.dart';

/// The §5 scope algebra at 0.8.2.24/.25 — the two rulings that changed what an
/// existing matcher must answer, plus the call-site enumeration RULE F asks for.
///
/// UNIT-level on purpose. §5.5a attenuation and the id-scope/path-scope split are
/// decided inside pure functions whose inputs a wire drive cannot reach directly:
/// `arc-probe` can show a grant being honoured or refused, it cannot show WHICH
/// matcher decided. The pinned 778-check set has no vector on either.
void main() {
  const local = 'z6MkLocalPeerIdThatIsNotRealButIsLongEnoughToPassBase58Check';

  Scope sc(List<String> incl, [List<String> excl = const []]) => Scope(incl, excl);

  /// A grant whose four dimensions move independently.
  GrantRec grant({
    Scope? handlers,
    Scope? resources,
    Scope? operations,
    Scope? peers,
  }) =>
      GrantRec(handlers ?? sc(['*']), resources ?? sc(['*']),
          operations ?? sc(['*']), peers);

  group('the sentinel is scoped to path-scope (0.8.2.24 N2/N3)', () {
    // §5.4 at 0.8.2.24: "a capability carrying an unmatchable PATH-SCOPE pattern is
    // INVALID ... It does NOT reach `operations` or `peers` [MUST]".
    //
    // The un-scoped form shipped at 0.8.2.21 transcribed §5.2's exclude loop before
    // that loop grew its type dispatch, so an id-scope pattern was run through the
    // §5.4 PATH transforms purely to classify it and the whole dimension was then
    // denied on a property unrelated to whether the exclude carves anything out.

    test('an operations exclude that path-canonicalizes to the sentinel does NOT deny',
        () {
      // `*/apply` is an ordinary namespaced operation name. Under the id-scope
      // grammar it is a LITERAL that matches nothing — a non-match, never a fault;
      // under the §5.4 path transforms it canonicalizes to the sentinel. Before the
      // fix this denied EVERY operation. Over-denial, invisible on a well-formed
      // grant.
      expect(canonicalize(local, '*/apply'), equals(neverMatch));
      expect(matchesScope(local, 'get', sc(['*'], ['*/apply']), ScopeKind.id),
          isTrue);
    });

    test('the same exclude on a PATH-scope dimension still denies (0.8.2.21 intact)',
        () {
      // The control that says the fix SCOPED the guard rather than deleting it. An
      // unmatchable exclude left to the matcher is fail-OPEN — it carves out nothing
      // and the grant is silently wider than its author wrote — so on a path-scope
      // dimension it must still deny.
      expect(
          matchesScope(local, 'system/tree', sc(['*'], ['*/apply']), ScopeKind.path),
          isFalse);
    });

    test('a peers exclude naming a relative-traversal form does not deny', () {
      // The second id-scope dimension, driven independently: a claim about
      // `operations` alone would not say the guard moved off `peers` too.
      expect(canonicalize(local, '../elsewhere'), equals(neverMatch));
      expect(
          matchesScope(local, local, sc([local], ['../elsewhere']), ScopeKind.id),
          isTrue);
    });

    test('an ordinary MATCHABLE exclude still excludes on both scope kinds', () {
      // The FIXTURE control. Accept cases alone cannot tell a working matcher from
      // one that allows everything; deny cases alone cannot tell it from one that
      // denies everything.
      expect(matchesScope(local, 'get', sc(['*'], ['get']), ScopeKind.id), isFalse);
      expect(
          matchesScope(
              local, 'system/tree', sc(['*'], ['system/tree']), ScopeKind.path),
          isFalse);
    });
  });

  group('scope_subset is typed by scope kind (F50, ruled 0.8.2.16)', () {
    // §3.6's grammar binds the SCOPE TYPE, not one function: "An implementation on
    // the canonicalizing reading is non-conformant and MUST adopt the literal
    // matcher." F40 typed `matchesScope`; its §5.5a sibling was left on the path
    // matcher for all four dimensions.
    //
    // Driven through `grantSubset`, the public call site — a test of the private
    // helper would prove it CAN dispatch and say nothing about whether the four
    // dimensions NAME their kind.

    test('an operations include the ID matcher covers is a subset of a bare star',
        () {
      // The formalization's witness. Under the path matcher the parent canonicalizes
      // to `/{parent}/*` and the child to the sentinel, so the pair was refused.
      // FAIL-CLOSED, which is exactly why no hand-tried example found it: nothing is
      // over-granted, legitimate delegation is refused.
      expect(
          grantSubset(local, local, local, grant(operations: sc(['*/apply'])),
              grant(operations: sc(['*']))),
          isTrue);
    });

    test('the second witness: an absolute-looking operation name under a star', () {
      expect(
          grantSubset(local, local, local, grant(operations: sc(['/tree/get'])),
              grant(operations: sc(['*']))),
          isTrue);
    });

    test('the SAME two patterns on RESOURCES are still path-matched (refused)', () {
      // THE DIFFERENTIAL that attributes the two rows above to the scope TYPE rather
      // than to `grantSubset` having been loosened.
      expect(
          grantSubset(local, local, local, grant(resources: sc(['*/apply'])),
              grant(resources: sc(['*']))),
          isFalse);
      expect(
          grantSubset(local, local, local, grant(resources: sc(['/tree/get'])),
              grant(resources: sc(['*']))),
          isFalse);
    });

    test('an operations include no parent include covers is still refused', () {
      // The accept rows cannot distinguish "the id matcher was used" from "the
      // operations dimension stopped being checked".
      expect(
          grantSubset(local, local, local, grant(operations: sc(['put'])),
              grant(operations: sc(['get']))),
          isFalse);
    });

    test('a parent operations EXCLUDE not inherited by the child is refused', () {
      // The exclude arm of the subset test on the id dimension, independently: the
      // include arm alone would not say the exclude arm is typed.
      expect(
          grantSubset(local, local, local, grant(operations: sc(['*'])),
              grant(operations: sc(['*'], ['delete']))),
          isFalse);
      expect(
          grantSubset(local, local, local, grant(operations: sc(['*'], ['delete'])),
              grant(operations: sc(['*'], ['delete']))),
          isTrue);
    });
  });

  group('the sentinel guard is reached from every match decision (RULE F, K-6)', () {
    // 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the
    // guard MUST sit on every path that reaches the decision it protects." The `lean`
    // bypass was a GUARDED WRAPPER beside an UNGUARDED running matcher, with
    // attenuation calling the raw one.
    //
    // ALREADY SATISFIED BY CONSTRUCTION HERE, and these cases are the measurement
    // that says so rather than a claim. `matchesPattern` is the single definition and
    // the sentinel test is its FIRST statement, so the bypass shape cannot occur: the
    // six call sites in lib/ (its own recursion, `_covered`, `_coveredFrame`,
    // `effectiveTargets`'s caller-exclude arm, and `_scopeSubset`'s two path arms)
    // all reach the same guarded body.
    //
    // WHICH OF THESE THE GUARD IS LOAD-BEARING FOR WAS MEASURED, NOT ASSUMED.
    // Deleting the guard and re-running shows the pattern-operand half is unreachable
    // as a discriminator here: `matchesPattern(x, neverMatch)` can only be true when
    // `x == neverMatch`, because the sentinel is neither a bare star, nor a `/*/`
    // form, nor a `/*` suffix, so every other arm falls through to the literal
    // compare and answers false on its own. A case that passes with the guard deleted
    // is not a control for the guard — it is a control for the fall-through.

    test('refuses the sentinel as the PATH operand', () {
      // The arm that makes the guard load-bearing: a bare star returns true for
      // anything, so safety must not rest on a value merely LOOKING unmatchable.
      expect(matchesPattern(neverMatch, '*'), isFalse);
    });

    test('refuses the sentinel against ITSELF', () {
      // The case a guard written as `path != pattern` would pass, and the only input
      // where the PATTERN-operand half decides anything.
      expect(matchesPattern(neverMatch, neverMatch), isFalse);
    });

    test('the guard is reached through ATTENUATION, not only through matchesScope',
        () {
      // The `lean` defect in this peer's own shape. The parent include is `/*` and
      // NOT a bare `*` deliberately: a bare star canonicalizes to `/{parent}/*`,
      // which refuses a sentinel child by prefix alone and would make this case pass
      // with the guard deleted. `/*` is already absolute, survives canonicalization
      // unchanged, and its `/*` suffix arm covers any path beginning with a slash —
      // including the sentinel. Only the guard refuses it.
      expect(
          grantSubset(local, local, local, grant(resources: sc(['../escape'])),
              grant(resources: sc(['/*']))),
          isFalse);
    });
  });
}
