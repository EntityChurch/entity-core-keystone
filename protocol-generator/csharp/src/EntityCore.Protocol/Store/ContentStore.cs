using System.Collections.Concurrent;
using EntityCore.Protocol.Emit;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Store;

/// <summary>
/// The content store (V7 §1.7): an immutable, deduplicated <c>Hash → Entity</c>
/// map. This is the in-memory minimal implementation the core peer ships with;
/// storage backends are implementation-defined (§1.10). Puts are idempotent on
/// content hash (§6.10 store step fires no event on re-put).
/// </summary>
internal sealed class ContentStore
{
    private readonly ConcurrentDictionary<string, Entity> _byHash = new();
    private readonly EmitBus? _emit;

    public ContentStore(EmitBus? emit = null) => _emit = emit;

    /// <summary>
    /// Store an entity, keyed by its content hash. Idempotent. The §6.10 Store step:
    /// a content-store event fires only when the entity is new to the store (a re-put
    /// of an existing hash fires nothing). A direct <c>content_store.put</c> executes
    /// only this step (no Bind / tree-change event).
    /// </summary>
    public void Put(Entity entity)
    {
        if (_byHash.TryAdd(entity.ContentHashHex, entity))
        {
            _emit?.EmitContentStore(entity);
        }
    }

    /// <summary>Retrieve an entity by content hash; null on miss.</summary>
    public Entity? Get(ReadOnlySpan<byte> contentHash) =>
        _byHash.TryGetValue(Hashes.Hex(contentHash), out Entity? entity) ? entity : null;

    public bool Contains(ReadOnlySpan<byte> contentHash) => _byHash.ContainsKey(Hashes.Hex(contentHash));
}
