using System.Security.Cryptography;
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

public class PCKEManager(ISecureKeyGenerator secureKeyGenerator, IPasswordHasher passwordHasher, ICacher cacher)
{
    private static readonly char[] Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();

    private static string CacheKey(string code) => $"pkce:{code}";

    public async Task<string> New(SnowflakeId userId, SnowflakeId credentialId, string codeChallenge, string codeChallengeMethod, string redirectUri, bool rememberMe = false)
    {
        var code = secureKeyGenerator.Generate(Alphabet, 128);

        var hashedCode = passwordHasher.Hash(code);

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

    public async Task<Result<(SnowflakeId userId, SnowflakeId credentialId, bool rememberMe)>> Exchange(string code, string codeVerifier, string redirectUri)
    {
        var hashedCode = passwordHasher.Hash(code);

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

