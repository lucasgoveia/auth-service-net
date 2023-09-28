using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using FluentValidation;

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

public class ResetPasswordHandler
{
    private readonly IIdentityPasswordChanger _identityPasswordChanger;
    private readonly ISessionManager _sessionManager;
    private readonly IAuthenticationService _authenticationService;
    private readonly ITokenManager _tokenManager;

    public ResetPasswordHandler(IIdentityPasswordChanger identityPasswordChanger, ISessionManager sessionManager,
        IAuthenticationService authenticationService, ITokenManager tokenManager)
    {
        _identityPasswordChanger = identityPasswordChanger;
        _sessionManager = sessionManager;
        _authenticationService = authenticationService;
        _tokenManager = tokenManager;
    }

    public async Task<Result> Handle(ResetPassword req, CancellationToken ct)
    {
        await _identityPasswordChanger.ResetPassword(_sessionManager.IdentityId!.Value, req.NewPassword, ct);
        await _sessionManager.TerminateSession();
        _tokenManager.RemoveLimitedAccessToken();
        await _authenticationService.LogOutAllSessions(ct);
        
        return SuccessResult.Success();
    }
}