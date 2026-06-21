using System.Runtime.InteropServices;
using EntityCore.Protocol;
using EntityCore.Protocol.Identity;

// ---------------------------------------------------------------------------
// entity-core-protocol-csharp — standalone peer host.
//
// The runnable target for S4 conformance: boots a single Peer listener on a TCP
// port and blocks until signalled, so an external oracle (entity-core-go
// validate-peer) can drive the live wire surface against it.
//
//   --port N               listen port (default 7777; 0 = auto-assign)
//   --debug-open-grants    DEPRECATED (v7.74 §6.9a; removed v7.75) — selects the
//                          degenerate `default → *` seed policy so every
//                          authenticating identity receives a wide-open admin
//                          grant. Routes through the real §6.9a seed-policy
//                          mechanism, not a hardcoded fork. Lets validate-peer
//                          reach grant-gated paths. Prefer --seed-policy.
//   --validate             Conformance build (GUIDE-CONFORMANCE §7a): register the
//                          `system/validate/*` test-handlers (echo +
//                          dispatch-outbound) so a black-box validator can drive
//                          the §6.13(a)/(b) extensibility hooks. NOT core protocol;
//                          OFF by default (dispatch-outbound is an outbound
//                          originator that must never ship live in production).
//   --name NAME            Load a persistent Ed25519 identity from the standard
//                          on-disk location ~/.entity/peers/NAME/keypair (the
//                          entity-core PEM keypair: a base64-encoded 32-byte seed
//                          between BEGIN/END ENTITY PRIVATE KEY lines — the same
//                          convention the Go entity-peer --name and peer-manager
//                          use). Without --name a fresh ephemeral identity is
//                          generated. Lets the validator's multisig accept-path
//                          probe (valid_2of3_peer_signed_accepted) find the peer's
//                          keypair on disk (crypto.LookupKeypairByPeerID) and
//                          co-sign AS the peer.
//
// The peer binds loopback (127.0.0.1); run the validator in the same network
// namespace (same container / pod).
// ---------------------------------------------------------------------------

int port = 7777;
bool openGrants = false;
bool validate = false;
PeerIdentity? identity = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port":
            if (i + 1 >= args.Length || !int.TryParse(args[++i], out port))
            {
                Console.Error.WriteLine("error: --port requires an integer argument");
                return 2;
            }
            break;
        case "--debug-open-grants":
            openGrants = true;
            Console.Error.WriteLine(
                "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — " +
                "it now selects the degenerate `default → *` seed policy. Prefer --seed-policy.");
            break;
        case "--validate":
            validate = true;
            break;
        case "--name":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("error: --name requires a NAME argument");
                return 2;
            }
            identity = LoadIdentityFromName(args[++i]);
            break;
        case "-h":
        case "--help":
            Console.WriteLine("usage: host [--port N] [--debug-open-grants] [--validate] [--name NAME]");
            return 0;
        default:
            Console.Error.WriteLine($"error: unknown argument '{args[i]}'");
            return 2;
    }
}

await using var peer = new Peer(identity: identity, debugOpenGrants: openGrants, conformanceHandlers: validate);
peer.ListenAsync(port);

// Single readiness line on stdout — a run script waits for "LISTENING" before
// pointing the validator at the port.
Console.WriteLine($"LISTENING 127.0.0.1:{peer.Port} peer_id={peer.LocalPeerId} open_grants={openGrants} validate={validate}");

// Block until SIGINT (Ctrl+C) or SIGTERM (podman stop / kill).
var stop = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.TrySetResult(); };
using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
{
    ctx.Cancel = true;
    stop.TrySetResult();
});
await stop.Task;

Console.WriteLine("shutting down");
return 0;

// Load the 32-byte Ed25519 seed from the standard on-disk keypair (the Go
// entity-peer --name / peer-manager convention): ~/.entity/peers/NAME/keypair,
// a PEM whose body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
// Errors (missing file, malformed body, wrong seed length) print to stderr and
// exit non-zero so a misconfigured run fails loud rather than running with a
// silently-wrong identity.
static PeerIdentity LoadIdentityFromName(string name)
{
    string home = Environment.GetEnvironmentVariable("HOME") ?? "/root";
    string path = Path.Combine(home, ".entity", "peers", name, "keypair");

    string[] lines;
    try
    {
        lines = File.ReadAllLines(path);
    }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"error: --name {name}: cannot read {path}: {e.Message}");
        Environment.Exit(2);
        throw; // unreachable; satisfies the compiler's definite-return analysis
    }

    // Body = the base64 line(s) between the markers; ignore lines starting with '-'.
    string body = string.Concat(lines.Where(l => !l.StartsWith('-'))).Trim();

    byte[] seed;
    try
    {
        seed = Convert.FromBase64String(body);
    }
    catch (FormatException e)
    {
        Console.Error.WriteLine($"error: --name {name}: malformed base64 in {path}: {e.Message}");
        Environment.Exit(2);
        throw; // unreachable
    }

    if (seed.Length != 32)
    {
        Console.Error.WriteLine(
            $"error: --name {name}: expected a 32-byte seed, got {seed.Length} bytes");
        Environment.Exit(2);
    }

    return PeerIdentity.FromSeed(seed);
}
