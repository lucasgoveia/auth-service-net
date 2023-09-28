using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record VerifyEmail
{
    public required string Code { get; init; }
}

public class VerifyEmailValidator : AbstractValidator<VerifyEmail>
{
    public VerifyEmailValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty()
            .Length(OtpGenerator.CodeLength);
    }
}

public class VerifyEmailHandler
{
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly UtcNow _utcNow;
    private readonly ISessionManager _sessionManager;
    private readonly IAccountEmailVerifiedSetter _accountEmailVerifiedSetter;

    public VerifyEmailHandler(IEmailVerificationManager emailVerificationManager, UtcNow utcNow,
        ISessionManager sessionManager,
        IAccountEmailVerifiedSetter accountEmailVerifiedSetter)
    {
        _emailVerificationManager = emailVerificationManager;
        _utcNow = utcNow;
        _sessionManager = sessionManager;
        _accountEmailVerifiedSetter = accountEmailVerifiedSetter;
    }

    public async Task<Result> Handle(VerifyEmail req, CancellationToken ct = default)
    {
        var userId = _sessionManager.UserId!.Value;

        var validCode = await _emailVerificationManager.Verify(userId, req.Code);

        if (!validCode)
        {
            return ErrorResult.Invalid();
        }

        await _emailVerificationManager.RevokeCode(userId);
        await _accountEmailVerifiedSetter.Set(userId, _utcNow(), ct);

        return SuccessResult.Success();
    }
}

public interface IAccountEmailVerifiedSetter
{
    Task Set(long userId, DateTime utcNow, CancellationToken ct = default);
}

public class AccountEmailVerifiedSetter : IAccountEmailVerifiedSetter
{
    private readonly IDbConnection _dbConnection;

    public AccountEmailVerifiedSetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Set(long userId, DateTime utcNow, CancellationToken ct = default)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET email_verified = true, updated_at = @utcNow WHERE id = @userId",
            new { userId, utcNow });
    }
}