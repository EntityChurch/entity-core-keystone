using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>Helpers for building <c>system/protocol/error</c> handler results (V7 §3.3).</summary>
internal static class Errors
{
    /// <summary>Build a handler result carrying a <c>system/protocol/error</c> entity.</summary>
    public static HandlerResult Error(int status, string code, string? message = null)
    {
        Entity error = Entity.Create(TypeNames.Error, Ecf.Map(
            ("code", Ecf.Text(code)),
            ("message", message is null ? null : Ecf.Text(message))));
        return HandlerResult.Of(status, error);
    }
}
