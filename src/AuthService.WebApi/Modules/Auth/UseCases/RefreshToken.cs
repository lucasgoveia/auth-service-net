using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Result;

namespace AuthService.WebApi.Modules.Auth.UseCases;

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

    public async Task<Result<RefreshTokenResponse>> Handle(CancellationToken ct = default)
    {
        return (await _authenticationService.RefreshToken(ct))
            .Map(accessToken => new RefreshTokenResponse { AccessToken = accessToken });
    }
}