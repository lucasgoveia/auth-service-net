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

public class LimitedSessionAuthentication
{
    public const string Scheme = nameof(LimitedSessionAuthentication);
}

public class LimitedSessionAuthenticationOptions : AuthenticationSchemeOptions
{
    public static CustomJwtAuthenticationOptions Instance = new();
}

public class LimitedSessionAuthenticationHandler(IOptionsMonitor<LimitedSessionAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, ISessionManager sessionManager,
        IOptions<JwtConfig> jwtConfig, UtcNow utcNow)
    : AuthenticationHandler<LimitedSessionAuthenticationOptions>(options, logger, encoder, clock)
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.ContainsKey(AuthCookieNames.LimitedAccessToken))
            return AuthenticateResult.Fail("Unauthorized");

        if (!Request.Cookies.TryGetValue(AuthCookieNames.LimitedAccessToken, out var limitedSessionCookie))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        if (string.IsNullOrEmpty(limitedSessionCookie))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var (validatedToken, valid) = await ValidateToken(limitedSessionCookie);

        if (!valid || validatedToken is null)
            return AuthenticateResult.Fail("Unauthorized");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, validatedToken.Subject, ClaimValueTypes.Integer64),
            new(CustomJwtClaimsNames.IdentityId,
                validatedToken.Claims.First(x => x.Type == CustomJwtClaimsNames.IdentityId).Value,
                ClaimValueTypes.Integer64),
            new(CustomJwtClaimsNames.LimitedSession, true.ToString(), ClaimValueTypes.Boolean),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new GenericPrincipal(identity, null);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        
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
            LifetimeValidator = (_, expires, _, _) => expires >= utcNow(),
            ClockSkew = TimeSpan.Zero,
        };

        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            var jwtToken = (validatedToken as JwtSecurityToken)!;
            return (jwtToken, true);
        }
        catch (SecurityTokenException)
        {
            return (null, false);
        }
    }
}