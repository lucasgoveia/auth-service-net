using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Results;

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
    private readonly IAuthenticationService _authenticationService;

    public RefreshTokenHandler(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    public async Task<Result<RefreshTokenResponse>> Handle(RefreshToken req, CancellationToken ct = default)
    {
        return (await _authenticationService.RefreshToken(ct))
            .Map(accessToken => new RefreshTokenResponse { AccessToken = accessToken });
    }
}