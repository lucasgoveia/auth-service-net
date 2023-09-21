using System.Data;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Results;
using AuthService.WebApi.Common.Timestamp;
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
            .Length(IEmailVerificationCodeGenerator.CodeLength);
    }
}

public class VerifyEmailHandler
{
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly UtcNow _utcNow;
    private readonly ISessionManager _sessionManager;
    private readonly IAccountEmailVerifiedSetter _accountEmailVerifiedSetter;

    public VerifyEmailHandler(IEmailVerificationManager emailVerificationManager, UtcNow utcNow, ISessionManager sessionManager,
        IAccountEmailVerifiedSetter accountEmailVerifiedSetter)
    {
        _emailVerificationManager = emailVerificationManager;
        _utcNow = utcNow;
        _sessionManager = sessionManager;
        _accountEmailVerifiedSetter = accountEmailVerifiedSetter;
    }

    public async Task<Result> Handle(VerifyEmail req, CancellationToken ct = default)
    {
        var accountId = _sessionManager.IdentityId;

        if (!accountId.HasValue)
        {
            throw new InvalidOperationException();
        }

        var validCode = await _emailVerificationManager.Verify(accountId.Value, req.Code);

        if (!validCode)
        {
            return ErrorResult.Invalid();
        }

        await _accountEmailVerifiedSetter.Set(accountId.Value, _utcNow(), ct);

        return SuccessResult.Success();
    }
}

public interface IAccountEmailVerifiedSetter
{
    Task Set(long accountId, DateTime utcNow, CancellationToken ct = default);
}

public class AccountEmailVerifiedSetter : IAccountEmailVerifiedSetter
{
    private readonly IDbConnection _dbConnection;

    public AccountEmailVerifiedSetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Set(long accountId, DateTime utcNow, CancellationToken ct = default)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Identities} SET email_verified = true, updated_at = @UtcNow WHERE id = @AccountId",
            new { AccountId = accountId, UtcNow = utcNow });
    }
}