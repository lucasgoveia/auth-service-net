using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.WebApi.Common.Auth;
using Dapper;
using FluentValidation;

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
}

public class ChangePasswordHandler
{
    private readonly IIdentityPasswordChanger _identityPasswordChanger;
    private readonly ISessionManager _sessionManager;
    private readonly IAuthenticationService _authenticationService;

    public ChangePasswordHandler(IIdentityPasswordChanger identityPasswordChanger, ISessionManager sessionManager,
        IAuthenticationService authenticationService)
    {
        _identityPasswordChanger = identityPasswordChanger;
        _sessionManager = sessionManager;
        _authenticationService = authenticationService;
    }

    public async Task<Result<ChangePasswordResponse>> Handle(ChangePassword req, CancellationToken ct)
    {
        var changePasswordResult = await _identityPasswordChanger.ChangePassword(_sessionManager.IdentityId!.Value,
            req.CurrentPassword, req.NewPassword, ct);

        if (!changePasswordResult.Success)
            return changePasswordResult.AsError()!;

        if (req.LogOutAllSessions)
        {
            await _authenticationService.LogOutAllSessions(ct);
        }

        var accessToken = await _authenticationService.Authenticate(_sessionManager.UserId!.Value,
            _sessionManager.IdentityId!.Value, true, ct);

        return SuccessResult.Success(new ChangePasswordResponse
        {
            AccessToken = accessToken
        });
    }
}

public interface IIdentityPasswordChanger
{
    Task<Result> ChangePassword(long identityId, string oldPassword, string newPassword, CancellationToken ct);
    Task ResetPassword(long identityId, string newPassword, CancellationToken ct);
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

    public async Task<Result> ChangePassword(long identityId, string oldPassword, string newPassword,
        CancellationToken ct)
    {
        var oldPasswordVerified = await VerifyOldPassword(identityId, oldPassword, ct);

        if (!oldPasswordVerified)
        {
            return ErrorResult.Unauthorized();
        }

        var newPassHash = _passwordHasher.Hash(newPassword);
        await PersistNewPassword(identityId, newPassHash, ct);
        return SuccessResult.Success();
    }

    public async Task ResetPassword(long identityId, string newPassword, CancellationToken ct)
    {
        var newPassHash = _passwordHasher.Hash(newPassword);
        await PersistNewPassword(identityId, newPassHash, ct);
    }

    private async Task PersistNewPassword(long identityId, string newPassword, CancellationToken ct)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Identities} SET password_hash = @newPassword WHERE Id = @identityId",
            new { identityId, newPassword });
    }

    private async Task<bool> VerifyOldPassword(long identityId, string oldPassword, CancellationToken ct)
    {
        var identityOldPassHash = await _dbConnection.QuerySingleAsync<string>(
            $"SELECT password_hash FROM {TableNames.Identities} WHERE Id = @identityId", new { identityId });
        return _passwordHasher.Verify(oldPassword, identityOldPassHash);
    }
}