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

public class RefreshTokenHandler
{
    private readonly ITokenManager _tokenManager;

    public RefreshTokenHandler(ITokenManager tokenManager)
    {
        _tokenManager = tokenManager;
    }

    public async Task<Result<RefreshTokenResponse>> Handle(RefreshToken req, CancellationToken ct = default)
    {
        return (await _tokenManager.RefreshToken(ct))
            .Map(accessToken => new RefreshTokenResponse { AccessToken = accessToken });
    }
}