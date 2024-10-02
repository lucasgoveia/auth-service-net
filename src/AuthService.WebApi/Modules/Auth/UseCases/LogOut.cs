using AuthService.WebApi.Common.Auth;
using LucasGoveia.Results;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record LogOut
{
    public static LogOut Instance { get; } = new();
}

public class LogOutHandler(IAuthenticationService authenticationService)
{
    public async Task<Result> Handle(LogOut req, CancellationToken ct = default)
    {
        await authenticationService.LogOut(ct);
        return Result.Ok();
    }
}