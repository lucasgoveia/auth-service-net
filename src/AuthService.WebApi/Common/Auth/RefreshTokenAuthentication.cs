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
    public static CustomJwtAuthenticationOptions Instance = new();
}

public class RefreshTokenAuthenticationHandler : AuthenticationHandler<RefreshTokenAuthenticationOptions>
{
    private readonly ISessionManager _sessionManager;
    private readonly ITokenManager _tokenManager;
    private readonly JwtConfig _jwtConfig;
    private readonly UtcNow _utcNow;

    public RefreshTokenAuthenticationHandler(IOptionsMonitor<RefreshTokenAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, ISessionManager sessionManager,
        IOptions<JwtConfig> jwtConfig, UtcNow utcNow, ITokenManager tokenManager) : base(options, logger, encoder,
        clock)
    {
        _sessionManager = sessionManager;
        _utcNow = utcNow;
        _tokenManager = tokenManager;
        _jwtConfig = jwtConfig.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.ContainsKey(AuthCookieNames.RefreshTokenCookieName))
            return AuthenticateResult.Fail("Unauthorized");

        if (!Request.Cookies.TryGetValue(AuthCookieNames.RefreshTokenCookieName, out var refreshCookie))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        if (string.IsNullOrEmpty(refreshCookie))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var (validatedToken, valid) = await ValidateToken(refreshCookie);

        if (!valid || validatedToken is null)
            return AuthenticateResult.Fail("Unauthorized");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, validatedToken.Subject, ClaimValueTypes.Integer64),
            new(CustomJwtClaimsNames.IdentityId,
                validatedToken.Claims.First(x => x.Type == CustomJwtClaimsNames.IdentityId).Value,
                ClaimValueTypes.Integer64),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new GenericPrincipal(identity, null);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    private async Task<(JwtSecurityToken?, bool)> ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var session = await _sessionManager.GetActiveSession();

        if (session is null)
        {
            return (null, false);
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(session.SessionSecret));

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidateAudience = true,
            AudienceValidator =
                (audiences, _, _) => audiences.Any(),
            ValidIssuer = _jwtConfig.Issuer,
            ValidateLifetime = true,
            LifetimeValidator = (_, expires, _, _) => expires >= _utcNow(),
            ClockSkew = TimeSpan.Zero,
        };

        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            var jwtToken = (validatedToken as JwtSecurityToken)!;

            var refreshTokenInfo = await _tokenManager.GetRefreshTokenInfo();

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