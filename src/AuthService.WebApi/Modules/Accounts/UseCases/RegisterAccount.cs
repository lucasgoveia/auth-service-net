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

        RuleFor(x => x.Password)
            .NotEmpty();
    }
}

public sealed class RegisterAccountHandler
{
    private readonly INewAccountSaver _saver;
    private readonly UtcNow _utcNow;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly GenerateId _generateId;
    private readonly IAuthenticationService _authenticationService;

    public RegisterAccountHandler(INewAccountSaver saver, UtcNow utcNow, IPasswordHasher passwordHasher,
        IEmailVerificationManager emailVerificationManager, GenerateId generateId,
        IAuthenticationService authenticationService)
    {
        _saver = saver;
        _utcNow = utcNow;
        _passwordHasher = passwordHasher;
        _emailVerificationManager = emailVerificationManager;
        _generateId = generateId;
        _authenticationService = authenticationService;
    }

    public async Task<Result> Handle(RegisterAccount req, CancellationToken ct = default)
    {
        var hashedPassword = _passwordHasher.Hash(req.Password);
        var identityId = await _generateId();
        var userId = await _generateId();

        var account = Identity.CreateNewIdentity(userId, identityId, req.Email, hashedPassword, _utcNow());
        var user = User.CreateNewUser(userId, req.Email, _utcNow());

        await _saver.Save(user, account);

        await _emailVerificationManager.SendCode(userId, req.Email);

        await _authenticationService.AuthenticateLimited(userId, identityId, ct);

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