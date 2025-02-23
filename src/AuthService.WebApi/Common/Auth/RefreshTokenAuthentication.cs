using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using AuthService.Common.Timestamp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public static class RefreshTokenAuthentication
{
    public const string Scheme = nameof(RefreshTokenAuthentication);
}

public class RefreshTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public static RefreshTokenAuthenticationOptions Instance = new();
}

public class RefreshTokenAuthenticationHandler(IOptionsMonitor<RefreshTokenAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, ISessionManager sessionManager,
        IOptions<JwtConfig> jwtConfig, UtcNow utcNow, ITokenManager tokenManager)
    : AuthenticationHandler<RefreshTokenAuthenticationOptions>(options, logger, encoder,
    clock)
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.GetTokenFromCookie(AuthCookieNames.RefreshTokenCookieName);
        
        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var (validatedToken, valid) = await ValidateToken(token);

        if (!valid || validatedToken is null)
            return AuthenticateResult.Fail("Unauthorized");

        var ticket = JwtUtils.CreateAuthenticationTicket(validatedToken.Subject,
            validatedToken.Claims.First(x => x.Type == CustomJwtClaimsNames.IdentityId).Value, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    private async Task<(JwtSecurityToken?, bool)> ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var session = await sessionManager.GetActiveSession();

        if (session is null)
        {
            return (null, false);
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(session.SessionSecret));
        var validationParameters = JwtUtils.GetTokenValidationParameters(key, utcNow, _jwtConfig);
        
        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            var jwtToken = (validatedToken as JwtSecurityToken)!;

            var refreshTokenInfo = await tokenManager.GetRefreshTokenInfo();

            if (refreshTokenInfo is null)
            {
                return (null, false);
            }

            return refreshTokenInfo.UsageCount >= _jwtConfig.RefreshTokenAllowedRenewsCount
                ? (null, false)
                : (jwtToken, true);
        }
        catch (SecurityTokenException)
        {
            return (null, false);
        }
    }
}