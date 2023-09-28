using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using FluentValidation;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record VerifyPasswordRecoveryCode
{
    public required string Code { get; init; }
}

public class VerifyPasswordRecoveryCodeValidator : AbstractValidator<VerifyPasswordRecoveryCode>
{
    public VerifyPasswordRecoveryCodeValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty()
            .Length(OtpGenerator.CodeLength);
    }
}

public class VerifyPasswordRecoveryCodeHandler
{
    private readonly IPasswordRecoveryManager _passwordRecoveryManager;
    private readonly ISessionManager _sessionManager;

    public VerifyPasswordRecoveryCodeHandler(IPasswordRecoveryManager passwordRecoveryManager,
        ISessionManager sessionManager)
    {
        _passwordRecoveryManager = passwordRecoveryManager;
        _sessionManager = sessionManager;
    }

    public async Task<Result> Handle(VerifyPasswordRecoveryCode req, CancellationToken ct = default)
    {
        var userId = _sessionManager.UserId!.Value;

        var validCode = await _passwordRecoveryManager.Verify(userId, req.Code);

        if (!validCode)
        {
            return ErrorResult.Invalid();
        }

        await _sessionManager.AddSessionProperty(SessionPropertiesNames.VerifiedRecoveryCode, true);
        await _passwordRecoveryManager.RevokeCode(userId);
        return SuccessResult.Success();
    }
}