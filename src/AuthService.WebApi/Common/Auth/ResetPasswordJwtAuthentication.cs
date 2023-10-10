using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Encodings.Web;
using AuthService.Common.Timestamp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public static class ResetPasswordJwtAuthentication
{
    public const string Scheme = "ResetPasswordJwtAuthentication";
}

public class ResetPasswordJwtAuthenticationOptions : AuthenticationSchemeOptions
{
    public static ResetPasswordJwtAuthenticationOptions Instance = new();
}

public class ResetPasswordJwtAuthenticationHandler(IOptionsMonitor<ResetPasswordJwtAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<JwtConfig> jwtConfig, UtcNow utcNow,
        ITokenManager tokenManager)
    : AuthenticationHandler<ResetPasswordJwtAuthenticationOptions>(options, logger, encoder,
        clock)
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
            validatedToken.Claims.First(x => x.Type == CustomJwtClaimsNames.IdentityId).Value, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    private async Task<(JwtSecurityToken?, bool)> ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.ResetPasswordTokenSecret));
        var validationParameters = JwtUtils.GetTokenValidationParameters(key, utcNow, _jwtConfig);

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