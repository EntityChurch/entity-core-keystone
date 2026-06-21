using System.Collections.Concurrent;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Emit;

/// <summary>
/// Content-store event (V7 §6.10 Store step): carries <c>(hash, entity)</c> ONLY — NO
/// execution context (threading exec-context onto the Store event is non-conformant).
/// </summary>
internal sealed record ContentStoreEvent(byte[] Hash, Entity Entity);

/// <summary>
/// Tree-change event (V7 §6.10 Bind step / v7.74 §6.13(c) B2). The field inventory is
/// the normative contract; the C# field names are idiomatic (S6). <see cref="EventType"/>
/// ∈ {<c>created</c>, <c>modified</c>, <c>deleted</c>} per the null-hash derivation. A bind
/// to a <c>system/deletion-marker</c> fires <c>modified</c>, NOT <c>deleted</c> — the
/// classification keys on a null <see cref="NewHash"/> only, never on the bound entity's
/// type (the marker is a §6.3 listing-visibility convention, decoupled from emit).
/// </summary>
internal sealed record TreeChangeEvent(
    string EventType, string Path, byte[]? NewHash, byte[]? PreviousHash, EmitContext? Context);

/// <summary>The three tree-change event kinds and the §6.10 null-hash derivation rule.</summary>
internal static class TreeChangeKind
{
    public const string Created = "created";
    public const string Modified = "modified";
    public const string Deleted = "deleted";

    /// <summary><c>created</c> iff previous is null; <c>deleted</c> iff new is null; else <c>modified</c>.</summary>
    public static string Derive(byte[]? previousHash, byte[]? newHash) =>
        previousHash is null ? Created : newHash is null ? Deleted : Modified;
}

/// <summary>
/// An emit consumer (V7 §6.10 consumer-registration primitive) — the bare primitive: a
/// callable plus identifying metadata (<see cref="Name"/>). Delivery mode (sync-inline vs
/// async-broadcast) is impl-defined per §9.4; the core peer delivers sync-inline.
/// </summary>
internal interface IEmitConsumer
{
    /// <summary>Identifying metadata for the consumer registration.</summary>
    string Name { get; }

    void OnContentStore(ContentStoreEvent ev);

    void OnTreeChange(TreeChangeEvent ev);
}

/// <summary>
/// The emit pathway (V7 §6.10 / v7.74 §6.13(c)). Tree writes produce events; this bus
/// delivers them to registered consumers. The hook is LIVE even with zero consumers —
/// events are produced and discarded — so a future extension can register a consumer
/// (<see cref="RegisterConsumer"/>) without the peer being rebuilt. A core-only peer
/// registers zero consumers; the pathway is still reachable, which is the §6.13(c) MUST.
/// <para>
/// Delivery is sync-inline (impl-defined per §9.4): consumers run on the writing thread.
/// A consumer MUST NOT re-enter a tree write that would deadlock the bind lock — the
/// async-broadcast delivery mode (for re-entrant consumers) is an extension concern.
/// </para>
/// </summary>
internal sealed class EmitBus
{
    private readonly ConcurrentBag<IEmitConsumer> _consumers = new();

    /// <summary>Register an emit consumer (§6.10). Reachable at any time, incl. post-bootstrap.</summary>
    public void RegisterConsumer(IEmitConsumer consumer) => _consumers.Add(consumer);

    /// <summary>Whether any consumer is registered — the no-consumer fast path (events produced-and-discarded).</summary>
    public bool HasConsumers => !_consumers.IsEmpty;

    /// <summary>Fire the §6.10 Store-step content-store event (hash + entity only).</summary>
    public void EmitContentStore(Entity entity)
    {
        if (_consumers.IsEmpty)
        {
            return;
        }
        var ev = new ContentStoreEvent(entity.ContentHash, entity);
        foreach (IEmitConsumer c in _consumers)
        {
            c.OnContentStore(ev);
        }
    }

    /// <summary>Fire the §6.10 Bind-step tree-change event, deriving <c>event_type</c> from the hashes.</summary>
    public void EmitTreeChange(string path, byte[]? previousHash, byte[]? newHash, EmitContext? context)
    {
        if (_consumers.IsEmpty)
        {
            return;
        }
        var ev = new TreeChangeEvent(
            TreeChangeKind.Derive(previousHash, newHash), path, newHash, previousHash, context);
        foreach (IEmitConsumer c in _consumers)
        {
            c.OnTreeChange(ev);
        }
    }
}
