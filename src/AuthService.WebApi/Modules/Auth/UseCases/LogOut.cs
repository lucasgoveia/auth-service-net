using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Result;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public class LogOutHandler
{
    private readonly IAuthenticationService _authenticationService;

    public LogOutHandler(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    public async Task<Result> Handle(CancellationToken ct = default)
    {
        await _authenticationService.LogOut(ct);
        return SuccessResult.Success();
    }
}