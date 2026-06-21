using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// A typed view over a <c>system/protocol/execute/response</c> entity (V7 §3.3).
/// The second and final wire message type. Correlates to its EXECUTE by
/// <c>request_id</c> (§6.11 demux key).
/// </summary>
internal sealed class ExecuteResponse
{
    public ExecuteResponse(Entity entity)
    {
        if (entity.Type != TypeNames.ExecuteResponse)
        {
            throw new EntityProtocolException($"expected {TypeNames.ExecuteResponse}, got '{entity.Type}'");
        }
        Entity = entity;
    }

    public Entity Entity { get; }

    public string RequestId => Ecf.RequireText(Entity.Data, "request_id");

    public int StatusCode => checked((int)Ecf.RequireUint(Entity.Data, "status"));

    /// <summary>The result entity (materialized; §3.4).</summary>
    public Entity Result => Entity.FromDecoded(Ecf.Require(Entity.Data, "result"));

    public ulong? BudgetConsumed => Ecf.OptUint(Entity.Data, "budget_consumed");

    /// <summary>Build an EXECUTE_RESPONSE carrying a result entity.</summary>
    public static ExecuteResponse Build(string requestId, int status, Entity result, ulong? budgetConsumed = null)
    {
        EcfValue data = Ecf.Map(
            ("request_id", Ecf.Text(requestId)),
            ("status", Ecf.Uint((ulong)status)),
            ("result", new EcfValue.PreEncoded(result.WireBytes)),
            ("budget_consumed", budgetConsumed is null ? null : Ecf.Uint(budgetConsumed.Value)));
        return new ExecuteResponse(Entity.Create(TypeNames.ExecuteResponse, data));
    }

    /// <summary>
    /// Build an error EXECUTE_RESPONSE with a <c>system/protocol/error</c> result
    /// (§3.3): <c>{code, message?}</c>. The <c>code</c> field is required on error
    /// responses (§6.12 — its absence is itself a protocol violation).
    /// </summary>
    public static ExecuteResponse Error(string requestId, int status, string code, string? message = null)
    {
        Entity error = Entity.Create(TypeNames.Error, Ecf.Map(
            ("code", Ecf.Text(code)),
            ("message", message is null ? null : Ecf.Text(message))));
        return Build(requestId, status, error);
    }
}
