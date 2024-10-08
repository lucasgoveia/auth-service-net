﻿using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record VerifyPasswordRecoveryCode
{
    public required string Email { get; init; }
    public required string Code { get; init; }
}

public record VerifyPasswordRecoveryCodeResponse
{
    public required string ResetToken { get; init; }
}

public class VerifyPasswordRecoveryCodeValidator : AbstractValidator<VerifyPasswordRecoveryCode>
{
    public VerifyPasswordRecoveryCodeValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.Code)
            .NotEmpty()
            .Length(OtpGenerator.CodeLength);
    }
}

public class VerifyPasswordRecoveryCodeHandler(
    IPasswordRecoveryManager passwordRecoveryManager,
    ITokenManager tokenManager,
    IDbConnection dbConnection)
{
    public async Task<Result<VerifyPasswordRecoveryCodeResponse>> Handle(VerifyPasswordRecoveryCode req,
        CancellationToken ct = default)
    {
        var validCode = await passwordRecoveryManager.Verify(req.Email, req.Code);

        var userInfo = await dbConnection.QuerySingleOrDefaultAsync<(SnowflakeId id, SnowflakeId userId)?>(
            $"SELECT id, user_id FROM {TableNames.Identities} WHERE username = @Email", req);

        if (!validCode || userInfo is null)
        {
            return Result.Invalid();
        }

        var token = tokenManager.GenerateResetPasswordAccessToken(userInfo.Value.userId, userInfo.Value.id);
        await passwordRecoveryManager.RevokeCode(req.Email);
        return Result.Ok(new VerifyPasswordRecoveryCodeResponse { ResetToken = token });
    }
}