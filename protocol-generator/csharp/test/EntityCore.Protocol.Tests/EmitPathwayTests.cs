using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Emit;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Store;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// F3 (v7.74 §6.13(c) / §6.10) — the emit pathway. Verifies the consumer-registration
/// primitive is reachable, that the Store + Bind steps fire with the pinned field
/// inventory and <c>event_type</c> derivation, no-op suppression, and the
/// deletion-marker → <c>modified</c> rule (classification keys on null new_hash, not type).
/// </summary>
public sealed class EmitPathwayTests
{
    private sealed class Recorder : IEmitConsumer
    {
        public string Name => "test-recorder";
        public List<ContentStoreEvent> Stores { get; } = new();
        public List<TreeChangeEvent> Changes { get; } = new();
        public void OnContentStore(ContentStoreEvent ev) => Stores.Add(ev);
        public void OnTreeChange(TreeChangeEvent ev) => Changes.Add(ev);
    }

    private static (EntityTree tree, Recorder rec) NewTree()
    {
        var bus = new EmitBus();
        var rec = new Recorder();
        bus.RegisterConsumer(rec);
        var store = new ContentStore(bus);
        return (new EntityTree(store, bus), rec);
    }

    private static Entity E(string body) =>
        Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(("v", Ecf.Text(body))));

    [Fact]
    public void Create_Modify_Delete_DeriveEventType()
    {
        (EntityTree tree, Recorder rec) = NewTree();
        const string path = "/peer/app/x";

        tree.Put(path, E("one"));      // created (previous null)
        tree.Put(path, E("two"));      // modified (previous non-null)
        tree.Remove(path);            // deleted (new null)

        Assert.Equal(3, rec.Changes.Count);
        Assert.Equal(TreeChangeKind.Created, rec.Changes[0].EventType);
        Assert.Null(rec.Changes[0].PreviousHash);
        Assert.NotNull(rec.Changes[0].NewHash);

        Assert.Equal(TreeChangeKind.Modified, rec.Changes[1].EventType);
        Assert.NotNull(rec.Changes[1].PreviousHash);
        Assert.NotNull(rec.Changes[1].NewHash);

        Assert.Equal(TreeChangeKind.Deleted, rec.Changes[2].EventType);
        Assert.NotNull(rec.Changes[2].PreviousHash);
        Assert.Null(rec.Changes[2].NewHash);

        // Store step fired once per distinct entity (two puts of distinct bodies).
        Assert.Equal(2, rec.Stores.Count);
    }

    [Fact]
    public void ReBindToCurrentHash_SuppressesBindEvent()
    {
        (EntityTree tree, Recorder rec) = NewTree();
        const string path = "/peer/app/y";
        Entity e = E("same");

        tree.Put(path, e);
        tree.Put(path, e);  // re-bind to the current hash → no Bind event, no Store event

        Assert.Single(rec.Changes);   // only the first
        Assert.Single(rec.Stores);    // entity already in store on the second put
    }

    [Fact]
    public void DeletionMarkerBind_FiresModified_NotDeleted()
    {
        (EntityTree tree, Recorder rec) = NewTree();
        const string path = "/peer/app/z";

        tree.Put(path, E("live"));
        // Binding a deletion-marker is a real binding change with a non-null new_hash, so
        // event_type is `modified` — the marker is a §6.3 listing convention, not a delete.
        tree.Put(path, Entity.Create(TypeNames.DeletionMarker, Ecf.EmptyMap));

        Assert.Equal(2, rec.Changes.Count);
        Assert.Equal(TreeChangeKind.Modified, rec.Changes[1].EventType);
        Assert.NotNull(rec.Changes[1].NewHash);
    }
}
