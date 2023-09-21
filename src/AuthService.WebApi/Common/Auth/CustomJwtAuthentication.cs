using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using AuthService.WebApi.Common.Timestamp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public static class CustomJwtAuthentication
{
    public const string Scheme = nameof(CustomJwtAuthentication);
}

public class CustomJwtAuthenticationOptions : AuthenticationSchemeOptions
{
    public static CustomJwtAuthenticationOptions Instance = new();
}

public class CustomJwtAuthenticationHandler : AuthenticationHandler<CustomJwtAuthenticationOptions>
{
    private readonly IAuthenticationService _authenticationService;
    private readonly JwtConfig _jwtConfig;
    private readonly UtcNow _utcNow;


    public CustomJwtAuthenticationHandler(IOptionsMonitor<CustomJwtAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<JwtConfig> jwtConfig,
        IAuthenticationService authenticationService, UtcNow utcNow) : base(options, logger, encoder, clock)
    {
        _authenticationService = authenticationService;
        _utcNow = utcNow;
        _jwtConfig = jwtConfig.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.Fail("Unauthorized");

        var authorizationHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authorizationHeader))
        {
            return AuthenticateResult.NoResult();
        }

        if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var token = authorizationHeader.Substring("bearer".Length).Trim();


        var (validatedToken, valid) = await ValidateToken(token);

        if (valid && validatedToken is not null)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, validatedToken.Subject),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        return AuthenticateResult.Fail("Unauthorized");
    }

    private async Task<(JwtSecurityToken?, bool)> ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.AccessTokenSecret));

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
            
            if (!await _authenticationService.IsAccessTokenRevoked(long.Parse(jwtToken.Subject), token))
            {
                return (jwtToken, true);
            }

            return (null, false);
        }
        catch (SecurityTokenException)
        {
            return (null, false);
        }
    }
}