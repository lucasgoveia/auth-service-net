using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using AuthService.Common.Timestamp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
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

public class CustomJwtAuthenticationHandler(IOptionsMonitor<CustomJwtAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<JwtConfig> jwtConfig,
        UtcNow utcNow, ITokenManager tokenManager)
    : AuthenticationHandler<CustomJwtAuthenticationOptions>(options, logger, encoder, clock)
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.Fail("Unauthorized");

        var authorizationHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authorizationHeader))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var token = authorizationHeader.Substring("bearer".Length).Trim();

        var (validatedToken, valid) = await ValidateToken(token);

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
        var publicKeyBytes = Convert.FromBase64String(_jwtConfig.AccessTokenPublicKey);
        using var rsa = RSA.Create(4096);
        rsa.ImportRSAPublicKey(publicKeyBytes, out _);
        
        var key = new RsaSecurityKey(rsa);

        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
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

            if (!await tokenManager.IsAccessTokenRevoked(long.Parse(jwtToken.Subject), token))
            {
                return (jwtToken, true);
            }

            return (null, false);
        }
        catch (SecurityTokenException ex)
        {
            return (null, false);
        }
    }
}