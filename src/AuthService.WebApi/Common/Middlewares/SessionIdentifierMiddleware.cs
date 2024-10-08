using System.IdentityModel.Tokens.Jwt;
using AuthService.WebApi.Common.Auth;

namespace AuthService.WebApi.Common.Middlewares;

public class SessionIdentifierMiddleware(ISessionManager sessionManager) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var sessionId = context.Request.Cookies[AuthCookieNames.SessionId];
        if (sessionId is not null)
        {
            await sessionManager.SetActiveSessionById(sessionId);
            await next(context);
            return;
        }

        var token = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(token))
        {
            await next(context);
            return;
        }

        var tokenValue = token.Replace("Bearer ", "");
        var sessionOrchestrationId = ExtractSessionOrchestrationId(tokenValue);

        if (sessionOrchestrationId is not null)
        {
            await sessionManager.SetActiveSessionByOrchestrationId(sessionOrchestrationId);
        }

        await next(context);
    }

    private static string? ExtractSessionOrchestrationId(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var tokenS = handler.ReadToken(token) as JwtSecurityToken;
        return tokenS?.Claims.FirstOrDefault(x => x.Type == CustomJwtClaimsNames.SessionOrchestrationId)?.Value;
    }
}