using AuthService.Common.Results;
using AuthService.WebApi.Common.Auth;
using FluentValidation;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record Login
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required bool RememberMe { get; init; }
}

public class LoginValidator : AbstractValidator<Login>
{
    public LoginValidator()
    {
        RuleFor(x => x.Username).NotEmpty();
        RuleFor(x => x.Password).NotEmpty();
    }
}

public record LoginResponse
{
    public required string AccessToken { get; init; }
}

public class LoginHandler(IAuthenticationService authenticationService)
{
    public async Task<Result<LoginResponse>> Handle(Login req, CancellationToken ct = default)
    {
        var result = await authenticationService.LogIn(req.Username, req.Password, req.RememberMe, ct);
        return result.Map(accessToken => new LoginResponse { AccessToken = accessToken });
    }
}