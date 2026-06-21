using System.Collections.Concurrent;
using EntityCore.Protocol.Emit;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Store;

/// <summary>One entry in a tree listing (V7 §3.9): an optional bound hash and a child-path flag.</summary>
internal sealed record ListingEntry(byte[]? Hash, bool HasChildren);

/// <summary>
/// The entity tree (V7 §1.7): the mutable <c>URI → Hash</c> location index over the
/// immutable <see cref="ContentStore"/>. Paths are stored absolute
/// (<c>/{peer_id}/rest</c>, §1.4). Entity binding and child-path existence are
/// independent dimensions (§1.7) — a path may be both bound and a prefix.
/// <para>
/// A <c>tree_put</c> executes the §6.10 emit pathway: the Store step (via
/// <see cref="ContentStore.Put"/>) then the Bind step (a tree-change event when the
/// binding at the path actually changes — no event on a re-bind to the current hash).
/// </para>
/// </summary>
internal sealed class EntityTree
{
    private readonly ContentStore _contentStore;
    private readonly EmitBus? _emit;
    private readonly ConcurrentDictionary<string, byte[]> _index = new();
    private readonly object _bindLock = new();

    public EntityTree(ContentStore contentStore, EmitBus? emit = null)
    {
        _contentStore = contentStore;
        _emit = emit;
    }

    public ContentStore ContentStore => _contentStore;

    /// <summary>Store an entity in the content store and bind <paramref name="path"/> to its hash.</summary>
    public void Put(string path, Entity entity) => Put(path, entity, null);

    /// <summary>
    /// Store + bind, threading an optional §6.8a execution <paramref name="context"/> onto
    /// the Bind-step tree-change event. Core writes pass <c>null</c> (the slot is inert); an
    /// extension dispatching through the same path threads its chain context.
    /// </summary>
    public void Put(string path, Entity entity, EmitContext? context)
    {
        _contentStore.Put(entity); // §6.10 Store step (fires a content-store event if new).
        byte[]? previous;
        bool changed;
        lock (_bindLock)
        {
            _index.TryGetValue(path, out previous);
            changed = previous is null || !Hashes.Equal(previous, entity.ContentHash);
            _index[path] = entity.ContentHash;
        }
        // §6.10 Bind step — fired outside the lock; no-op re-bind to the current hash is suppressed.
        if (changed)
        {
            _emit?.EmitTreeChange(path, previous, entity.ContentHash, context);
        }
    }

    /// <summary>Remove the binding at <paramref name="path"/> (the entity stays in the content store).</summary>
    public void Remove(string path) => Remove(path, null);

    /// <summary>Unbind, firing a §6.10 <c>deleted</c> tree-change event (null new_hash) when a binding existed.</summary>
    public void Remove(string path, EmitContext? context)
    {
        byte[]? previous;
        bool wasBound;
        lock (_bindLock)
        {
            wasBound = _index.TryRemove(path, out previous);
        }
        if (wasBound)
        {
            _emit?.EmitTreeChange(path, previous, null, context);
        }
    }

    /// <summary>Get the entity bound at <paramref name="path"/>; null if unbound.</summary>
    public Entity? Get(string path) =>
        _index.TryGetValue(path, out byte[]? hash) ? _contentStore.Get(hash) : null;

    /// <summary>Get the content hash bound at <paramref name="path"/>; null if unbound.</summary>
    public byte[]? GetHash(string path) =>
        _index.TryGetValue(path, out byte[]? hash) ? hash : null;

    public bool IsBound(string path) => _index.ContainsKey(path);

    /// <summary>
    /// Conditional bind (CAS, §3.9). <paramref name="expectedHash"/> null =
    /// unconditional; zero = create-only (must be unbound); non-zero = must match
    /// the current binding. Returns false on a CAS miss.
    /// </summary>
    public bool CompareAndPut(string path, Entity entity, byte[]? expectedHash)
    {
        byte[]? previous;
        bool changed;
        lock (_bindLock)
        {
            byte[]? current = _index.TryGetValue(path, out byte[]? h) ? h : null;
            if (expectedHash is not null)
            {
                if (Hashes.IsZero(expectedHash))
                {
                    if (current is not null)
                    {
                        return false; // create-only, but a binding exists
                    }
                }
                else if (current is null || !Hashes.Equal(current, expectedHash))
                {
                    return false;
                }
            }
            _contentStore.Put(entity);
            previous = current;
            changed = previous is null || !Hashes.Equal(previous, entity.ContentHash);
            _index[path] = entity.ContentHash;
        }
        // §6.10 Bind step — fired outside the lock; a no-op re-bind is suppressed.
        if (changed)
        {
            _emit?.EmitTreeChange(path, previous, entity.ContentHash, null);
        }
        return true;
    }

    /// <summary>
    /// One level of entries under <paramref name="prefix"/> (a path ending in
    /// <c>/</c>). Each name maps to its bound hash (if any) and whether deeper
    /// child paths exist (§3.9).
    /// </summary>
    public IReadOnlyDictionary<string, ListingEntry> List(string prefix)
    {
        string normalized = prefix.EndsWith('/') ? prefix : prefix + "/";
        var directHash = new Dictionary<string, byte[]?>();
        var hasChildren = new HashSet<string>();

        foreach (KeyValuePair<string, byte[]> kv in _index)
        {
            if (!kv.Key.StartsWith(normalized, StringComparison.Ordinal))
            {
                continue;
            }
            string rest = kv.Key[normalized.Length..];
            if (rest.Length == 0)
            {
                continue;
            }
            int slash = rest.IndexOf('/');
            if (slash < 0)
            {
                directHash[rest] = kv.Value; // direct binding at prefix/name
            }
            else
            {
                hasChildren.Add(rest[..slash]); // a deeper path exists under prefix/name
            }
        }

        var entries = new Dictionary<string, ListingEntry>();
        foreach (string name in directHash.Keys.Union(hasChildren))
        {
            directHash.TryGetValue(name, out byte[]? hash);
            entries[name] = new ListingEntry(hash, hasChildren.Contains(name));
        }
        return entries;
    }
}
