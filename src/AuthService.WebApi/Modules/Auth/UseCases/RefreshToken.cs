using AuthService.WebApi.Common.Auth;
using LucasGoveia.Results;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record RefreshToken
{
    public static RefreshToken Instance { get; } = new();
}

public record RefreshTokenResponse
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
}

public class RefreshTokenHandler(ITokenManager tokenManager)
{
    public async Task<Result<RefreshTokenResponse>> Handle(RefreshToken req, CancellationToken ct = default)
    {
        return (await tokenManager.RefreshToken(ct))
            .Map((a) => new RefreshTokenResponse { AccessToken = a.accessToken, RefreshToken = a.refreshToken });
    }
}