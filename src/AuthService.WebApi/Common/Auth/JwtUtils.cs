using System.Security.Claims;
using System.Security.Principal;
using AuthService.Common.Timestamp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public static class JwtUtils
{
    public static string? GetTokenFromAuthorizationHeader(this HttpRequest request)
    {
        if (!request.Headers.ContainsKey("Authorization"))
            return null;

        var authorizationHeader = request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authorizationHeader))
        {
            return null;
        }

        if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = authorizationHeader.Substring("bearer".Length).Trim();

        return token;
    }
    

    public static AuthenticationTicket CreateAuthenticationTicket(string userId, string identityId, string scheme)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.Integer64),
            new(CustomJwtClaimsNames.CredentialId, identityId, ClaimValueTypes.Integer64),
        };

        var identity = new ClaimsIdentity(claims, scheme);
        var principal = new GenericPrincipal(identity, null);
        var ticket = new AuthenticationTicket(principal, scheme);
        return ticket;
    }
    
    public static TokenValidationParameters GetTokenValidationParameters(SecurityKey key, UtcNow utcNow, JwtConfig jwtConfig, TimeSpan? clockSkew = null)
    {
        return new TokenValidationParameters
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidateAudience = true,
            AudienceValidator =
                (audiences, _, _) => audiences.Any(),
            ValidIssuer = jwtConfig.Issuer,
            ValidateLifetime = true,
            LifetimeValidator = (_, expires, _, _) => expires >= utcNow(),
            ClockSkew = clockSkew ?? TimeSpan.Zero,
        };
    }
}