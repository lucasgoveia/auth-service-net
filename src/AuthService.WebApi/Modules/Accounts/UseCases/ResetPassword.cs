using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using FluentValidation;
using LucasGoveia.Results;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record ResetPassword
{
    public required string NewPassword { get; init; }
}

public class ResetPasswordValidator : AbstractValidator<ResetPassword>
{
    public ResetPasswordValidator(IPasswordPolicy passwordPolicy)
    {
        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .MustAsync(async (p, ct) => await passwordPolicy.IsValid(p));
    }
}

public class ResetPasswordHandler(
    IIdentityPasswordChanger identityPasswordChanger,
    ISessionManager sessionManager,
    IAuthenticationService authenticationService,
    ITokenManager tokenManager)
{
    public async Task<Result> Handle(ResetPassword req, CancellationToken ct)
    {
        await identityPasswordChanger.ResetPassword(sessionManager.IdentityId!.Value, req.NewPassword, ct);

        await tokenManager.RevokeAccessToken();
        await authenticationService.LogOutAllSessions(ct);

        return Result.Ok();
    }
}