using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Results;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record LogOut
{
    public static LogOut Instance { get; } = new();
}

public class LogOutHandler
{
    private readonly IAuthenticationService _authenticationService;

    public LogOutHandler(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    public async Task<Result> Handle(LogOut req, CancellationToken ct = default)
    {
        await _authenticationService.LogOut(ct);
        return SuccessResult.Success();
    }
}