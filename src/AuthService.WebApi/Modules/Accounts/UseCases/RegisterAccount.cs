using System.Data;
using AuthService.Common;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record RegisterAccount
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string? Name { get; init; }
}

public class RegisterAccountValidator : AbstractValidator<RegisterAccount>
{
    public RegisterAccountValidator(IUsernameAvailabilityChecker checker, IPasswordPolicy passwordPolicy)
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .MustAsync(async (e, ct) => await checker.IsAvailable(e, ct));

        RuleFor(x => x.Password)
            .NotEmpty()
            .MustAsync(async (p, ct) => await passwordPolicy.IsValid(p));

        RuleFor(x => x.Name)
            .NotEmpty()
            .MinimumLength(2);
    }
}

public sealed class RegisterAccountHandler(INewAccountSaver saver, UtcNow utcNow, IPasswordHasher passwordHasher,
    IEmailVerificationManager emailVerificationManager, GenerateId generateId,
    IAuthenticationService authenticationService)
{
    public async Task<Result> Handle(RegisterAccount req, CancellationToken ct = default)
    {
        var hashedPassword = passwordHasher.Hash(req.Password);
        var identityId = await generateId();
        var userId = await generateId();

        var account = Identity.CreateNewIdentity(userId, identityId, req.Email, hashedPassword, utcNow());
        var user = User.CreateNewUser(userId, req.Email, req.Name, utcNow());

        await saver.Save(user, account);

        await emailVerificationManager.SendCode(userId, req.Email);

        await authenticationService.AuthenticateLimited(userId, identityId, ct);

        return SuccessResult.Success();
    }
}

public interface INewAccountSaver
{
    Task Save(User user, Identity identity);
}

public class NewAccountSaver : INewAccountSaver
{
    private readonly IDbConnection _dbConnection;

    public NewAccountSaver(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Save(User user, Identity identity)
    {
        if (_dbConnection.State != ConnectionState.Open)
        {
            _dbConnection.Open();
        }

        using var transaction = _dbConnection.BeginTransaction();

        await _dbConnection.ExecuteAsync(
            $"INSERT INTO {TableNames.Users} (id, name, email, created_at, updated_at) VALUES (@Id, @Name, @Email, @CreatedAt, @UpdatedAt)",
            user);

        await _dbConnection.ExecuteAsync(
            @$"INSERT INTO {TableNames.Identities} (id, user_id, username, password_hash, created_at, updated_at) VALUES (@Id, @UserId, @Username, @PasswordHash, @CreatedAt, @UpdatedAt)",
            identity);

        transaction.Commit();
    }
}