using System.IdentityModel.Tokens.Jwt;
using AuthService.WebApi.Common.Auth;

namespace AuthService.WebApi.Common.Middlewares;

public class SessionIdentifierMiddleware(ISessionManager sessionManager, ILogger<SessionIdentifierMiddleware> logger) : IMiddleware
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

        await next(context);
    }


}