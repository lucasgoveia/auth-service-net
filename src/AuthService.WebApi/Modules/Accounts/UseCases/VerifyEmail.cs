﻿using System.Data;
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

public class VerifyEmailHandler(IEmailVerificationManager emailVerificationManager, UtcNow utcNow,
    ISessionManager sessionManager,
    IAccountEmailVerifiedSetter accountEmailVerifiedSetter)
{
    public async Task<Result> Handle(VerifyEmail req, CancellationToken ct = default)
    {
        var userId = sessionManager.UserId!.Value;

        var validCode = await emailVerificationManager.Verify(userId, req.Code);

        if (!validCode)
        {
            return ErrorResult.Invalid();
        }

        await emailVerificationManager.RevokeCode(userId);
        await accountEmailVerifiedSetter.Set(userId, utcNow(), ct);

        return SuccessResult.Success();
    }
}

public interface IAccountEmailVerifiedSetter
{
    Task Set(long userId, DateTime utcNow, CancellationToken ct = default);
}

public class AccountEmailVerifiedSetter(IDbConnection dbConnection) : IAccountEmailVerifiedSetter
{
    public async Task Set(long userId, DateTime utcNow, CancellationToken ct = default)
    {
        await dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET email_verified = true, updated_at = @utcNow WHERE id = @userId",
            new { userId, utcNow });
    }
}