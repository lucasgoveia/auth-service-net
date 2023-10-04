using AuthService.Common.Results;
using AuthService.WebApi.Common.Auth;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record RefreshToken
{
    public static RefreshToken Instance { get; } = new();
}

public record RefreshTokenResponse
{
    public required string AccessToken { get; init; }
}

public class RefreshTokenHandler(ITokenManager tokenManager)
{
    public async Task<Result<RefreshTokenResponse>> Handle(RefreshToken req, CancellationToken ct = default)
    {
        return (await tokenManager.RefreshToken(ct))
            .Map(accessToken => new RefreshTokenResponse { AccessToken = accessToken });
    }
}