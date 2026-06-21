import 'package:entity_core_protocol/src/conformance/harness.dart';
import 'package:test/test.dart';

/// The wire-conformance gate (the S2 codec gate): every vector in the v7.71
/// corpus must be byte-identical (encode) / correctly rejected (decode_reject).
/// A FAIL here means the CODE is wrong (S5 discipline) — never the corpus.
void main() {
  test('wire-conformance corpus is byte-identical (69/69)', () async {
    final result = await ConformanceHarness.run(ConformanceHarness.defaultFixture());
    if (result.failures.isNotEmpty) {
      // ignore: avoid_print
      print(result.failures.join('\n'));
    }
    // ignore: avoid_print
    print('== ECF conformance: ${result.pass}/${result.total} PASS, '
        '${result.fail} FAIL ==');
    expect(result.fail, 0, reason: result.failures.join('\n'));
    expect(result.pass, result.total);
    expect(result.total, 69, reason: 'expected 69 testable vectors in v7.71');
  });
}
