import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';

/// Standalone S4-ready host: boots a peer on a localhost port and prints a
/// `LISTENING <port>` line so a harness can scrape the bound port. Flags:
///
/// ```
///   --port N               bind port (0 = auto, the default)
///   --seed B               seed byte (repeated 32×) for a deterministic identity
///   --name NAME            load a persistent Ed25519 identity from the standard
///                          on-disk location ~/.entity/peers/NAME/keypair (the
///                          entity-core PEM keypair: base64 of a 32-byte seed
///                          between BEGIN/END ENTITY PRIVATE KEY lines — the Go
///                          entity-peer --name / peer-manager convention). Lets the
///                          validator's multisig accept-path probe co-sign AS the
///                          peer (crypto.LookupKeypairByPeerID).
///   --debug-open-grants    degenerate [default → *] admin seed (non-conformant)
///   --validate             bootstrap the §7a system/validate/* conformance handlers
/// ```
///
/// The §7a handlers are OFF by default (a standing dispatch-outbound originator
/// must never ship live); `--validate` opts in (the keystone cohort mechanism).
/// AOT-compiled for S4 (`dart compile exe bin/peer.dart`) per profile [build].
Future<void> main(List<String> args) async {
  var port = 0;
  var seedByte = 1;
  String? name;
  var openGrants = false;
  var validate = false;
  var i = 0;
  while (i < args.length) {
    switch (args[i]) {
      case '--port':
        port = int.parse(args[++i]);
      case '--seed':
        seedByte = int.parse(args[++i]);
      case '--name':
        name = args[++i];
      case '--debug-open-grants':
        openGrants = true;
      case '--validate':
        validate = true;
      default:
        break; // ignore unknown flags for forward-compat
    }
    i++;
  }
  final seed = name != null
      ? _loadSeedFromName(name)
      : (Uint8List(32)..fillRange(0, 32, seedByte));
  final peer =
      await Peer.create(seed, openGrants: openGrants, conformance: validate);
  final listener = await startListener(peer, port);
  stdout.writeln('LISTENING ${listener.port}');
  stdout.writeln('PEER ${peer.localPeer}');
  await stdout.flush();
  // park forever (the harness kills the process)
  await Completer<void>().future;
}

/// Load the 32-byte Ed25519 seed from the standard on-disk keypair at
/// `~/.entity/peers/NAME/keypair` — an entity-core PEM whose body is base64(seed)
/// between BEGIN/END ENTITY PRIVATE KEY lines. Missing or malformed → exit 2.
Uint8List _loadSeedFromName(String name) {
  final home = _firstNonEmpty([
    Platform.environment['HOME'],
    Platform.environment['USERPROFILE'],
  ]) ?? '/root';
  final path = '$home/.entity/peers/$name/keypair';
  try {
    final lines = File(path).readAsLinesSync();
    final body = lines
        .where((l) => !l.startsWith('-'))
        .map((l) => l.trim())
        .join();
    final seed = Uint8List.fromList(base64.decode(body));
    if (seed.length != 32) {
      stderr.writeln(
          'error: --name $name: expected a 32-byte seed, got ${seed.length} bytes');
      exit(2);
    }
    return seed;
  } catch (e) {
    stderr.writeln('error: --name $name: $e');
    exit(2);
  }
}

String? _firstNonEmpty(List<String?> xs) {
  for (final x in xs) {
    if (x != null && x.isNotEmpty) return x;
  }
  return null;
}
