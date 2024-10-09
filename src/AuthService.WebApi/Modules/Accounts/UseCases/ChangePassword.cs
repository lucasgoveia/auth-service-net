using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using Dapper;
using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record ChangePassword
{
    public required string CurrentPassword { get; init; }
    public required string NewPassword { get; init; }
    public required bool LogOutAllSessions { get; init; }
}

public class ChangePasswordValidator : AbstractValidator<ChangePassword>
{
    public ChangePasswordValidator(IPasswordPolicy passwordPolicy)
    {
        RuleFor(x => x.CurrentPassword).NotEmpty();
        RuleFor(x => x.NewPassword).NotEmpty();

        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .MustAsync(async (p, ct) => await passwordPolicy.IsValid(p));

        RuleFor(x => x)
            .Must(x => x.CurrentPassword != x.NewPassword);
    }
}

public record ChangePasswordResponse
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
}

public class ChangePasswordHandler(
    IIdentityPasswordChanger identityPasswordChanger,
    ISessionManager sessionManager,
    IAuthenticationService authenticationService)
{
    public async Task<Result<ChangePasswordResponse>> Handle(ChangePassword req, CancellationToken ct)
    {
        var changePasswordResult = await identityPasswordChanger.ChangePassword(sessionManager.IdentityId!.Value,
            req.CurrentPassword, req.NewPassword, ct);

        if (!changePasswordResult.IsSuccess)
            return changePasswordResult.AsError()!;

        if (req.LogOutAllSessions)
        {
            await authenticationService.LogOutAllSessions(ct);
        }

        var (accessToken, refreshToken) = await authenticationService.Authenticate(sessionManager.UserId!.Value,
            sessionManager.IdentityId!.Value, true, ct);

        return Result.Ok(new ChangePasswordResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }
}

public interface IIdentityPasswordChanger
{
    Task<Result> ChangePassword(SnowflakeId identityId, string oldPassword, string newPassword, CancellationToken ct);
    Task ResetPassword(SnowflakeId identityId, string newPassword, CancellationToken ct);
}

public class IdentityPasswordChanger : IIdentityPasswordChanger
{
    private readonly IDbConnection _dbConnection;
    private readonly IPasswordHasher _passwordHasher;

    public IdentityPasswordChanger(IDbConnection dbConnection, IPasswordHasher passwordHasher)
    {
        _dbConnection = dbConnection;
        _passwordHasher = passwordHasher;
    }

    public async Task<Result> ChangePassword(SnowflakeId identityId, string oldPassword, string newPassword,
        CancellationToken ct)
    {
        var oldPasswordVerified = await VerifyOldPassword(identityId, oldPassword, ct);

        if (!oldPasswordVerified)
        {
            return Result.Unauthorized();
        }

        var newPassHash = _passwordHasher.Hash(newPassword);
        await PersistNewPassword(identityId, newPassHash, ct);
        return Result.Ok();
    }

    public async Task ResetPassword(SnowflakeId identityId, string newPassword, CancellationToken ct)
    {
        var newPassHash = _passwordHasher.Hash(newPassword);
        await PersistNewPassword(identityId, newPassHash, ct);
    }

    private async Task PersistNewPassword(SnowflakeId identityId, string newPassword, CancellationToken ct)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Credentials} SET secret = @newPassword WHERE Id = @identityId",
            new { identityId, newPassword });
    }

    private async Task<bool> VerifyOldPassword(SnowflakeId identityId, string oldPassword, CancellationToken ct)
    {
        var identityOldPassHash = await _dbConnection.QuerySingleAsync<string>(
            $"SELECT secret FROM {TableNames.Credentials} WHERE Id = @identityId", new { identityId });
        return _passwordHasher.Verify(oldPassword, identityOldPassHash);
    }
}