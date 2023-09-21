using System.Data;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Results;
using AuthService.WebApi.Common.Security;
using Dapper;
using FluentValidation;
using ISession = AuthService.WebApi.Common.ISession;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record ChangePassword
{
    public required string CurrentPassword { get; init; }
    public required string NewPassword { get; init; }
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

public class ChangePasswordHandler
{
    private readonly IIdentityPasswordChanger _identityPasswordChanger;
    private readonly ISession _session;

    public ChangePasswordHandler(IIdentityPasswordChanger identityPasswordChanger, ISession session)
    {
        _identityPasswordChanger = identityPasswordChanger;
        _session = session;
    }

    public async Task<Result> Handle(ChangePassword req, CancellationToken ct)
    {
        // TODO: Add option for logging out of all sessions
        // TODO: Issue new access and refresh tokens
        return await _identityPasswordChanger.ChangePassword(_session.IdentityId!.Value, req.CurrentPassword,
            req.NewPassword, ct);
    }
}

public interface IIdentityPasswordChanger
{
    Task<Result> ChangePassword(long identityId, string oldPassword, string newPassword, CancellationToken ct);
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