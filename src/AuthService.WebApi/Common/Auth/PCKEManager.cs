using System.Security.Cryptography;
using System.Text;
using AuthService.Common.Caching;
using AuthService.Common.Security;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public record PCKEFlowData
{
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public required string RedirectUri { get; init; }
    public required SnowflakeId UserId { get; init; }
    public required SnowflakeId CredentialId { get; init; }
    public required bool RememberMe { get; set; }
}

public class PCKEManager(ISecureKeyGenerator secureKeyGenerator, ICacher cacher, ILogger<PCKEManager> logger)
{
    private static readonly char[] Alphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();

    private static string CacheKey(string code) => $"pkce:{code}";
    
    private static string DigestCode(string code)
    {
        using var sha256 = SHA256.Create();
        var hashedCode = sha256.ComputeHash(Encoding.UTF8.GetBytes(code)).Select(x => x.ToString("x2"))
            .Aggregate(new StringBuilder(), (sb, x) => sb.Append(x))
            .ToString();
        
        return hashedCode;
    }

    public async Task<string> New(SnowflakeId userId, SnowflakeId credentialId, string codeChallenge,
        string codeChallengeMethod, string redirectUri, bool rememberMe = false)
    {
        using var sha256 = SHA256.Create();
        var code = secureKeyGenerator.Generate(Alphabet, 128);

        var hashedCode = DigestCode(code);

        logger.LogDebug("New PKCE flow for code {Code} and user {UserId}", code, userId);
        logger.LogDebug("Hashed code {HashedCode}", hashedCode);

        await cacher.Set(CacheKey(hashedCode), new PCKEFlowData
        {
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RedirectUri = redirectUri,
            UserId = userId,
            CredentialId = credentialId,
            RememberMe = rememberMe
        }, TimeSpan.FromMinutes(5));

        return code;
    }

    public async Task<Result<(SnowflakeId userId, SnowflakeId credentialId, bool rememberMe)>> Exchange(string code,
        string codeVerifier, string redirectUri)
    {
        var hashedCode = DigestCode(code);

        logger.LogDebug("Exchanging PKCE flow for code {Code}", code);
        logger.LogDebug("Hashed code {HashedCode}", hashedCode);

        var data = await cacher.GetAndRemove<PCKEFlowData>(CacheKey(hashedCode));

        if (data is null)
        {
            return Result.Unauthorized();
        }

        if (data.CodeChallengeMethod != "S256")
        {
            return data.CodeChallenge == code && data.RedirectUri == redirectUri
                ? Result.Ok((data.UserId, data.CredentialId, data.RememberMe))
                : Result.Unauthorized();
        }

        using var sha256 = SHA256.Create();
        var codeVerifierHash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Base64UrlEncoder.Encode(codeVerifierHash);

        return codeChallenge == data.CodeChallenge && data.RedirectUri == redirectUri
            ? Result.Ok((data.UserId, data.CredentialId, data.RememberMe))
            : Result.Unauthorized();
    }
}