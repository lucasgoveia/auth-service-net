using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using AuthService.Common.Timestamp;
using LucasGoveia.SnowflakeId;
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
        RsaKeyHolder rsaKeyHolder, UtcNow utcNow, ITokenManager tokenManager)
    : AuthenticationHandler<CustomJwtAuthenticationOptions>(options, logger, encoder, clock)
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.GetTokenFromAuthorizationHeader();

        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var (validatedToken, valid) = await ValidateToken(token);

        if (!valid || validatedToken is null)
            return AuthenticateResult.Fail("Unauthorized");

        var ticket = JwtUtils.CreateAuthenticationTicket(validatedToken.Subject,
            validatedToken.Claims.First(x => x.Type == CustomJwtClaimsNames.CredentialId).Value, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    private async Task<(JwtSecurityToken?, bool)> ValidateToken(string token)
    {
        var key = rsaKeyHolder.GetPublicKey();

        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = JwtUtils.GetTokenValidationParameters(key, utcNow, _jwtConfig);

        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            var jwtToken = (validatedToken as JwtSecurityToken)!;

            if (!await tokenManager.IsAccessTokenRevoked(SnowflakeId.Parse(jwtToken.Subject, CultureInfo.InvariantCulture), token))
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