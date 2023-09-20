using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Result;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record Login
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required bool RememberMe { get; init; }
}

public record LoginResponse
{
    public required string AccessToken { get; init; }
}

public class LoginHandler
{
    private readonly IAuthenticationService _authenticationService;

    public LoginHandler(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    public async Task<Result<LoginResponse>> Handle(Login req, CancellationToken ct = default)
    {
        var result = await _authenticationService.LogIn(req.Username, req.Password, req.RememberMe, ct);

        return result.Map(accessToken => new LoginResponse { AccessToken = accessToken });
    }
}