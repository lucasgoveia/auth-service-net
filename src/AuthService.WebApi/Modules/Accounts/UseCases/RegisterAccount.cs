using System.Data;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Common.Security;
using AuthService.WebApi.Common.Timestamp;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record RegisterAccount
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string Fingerprint { get; init; }
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
    }
}

public record RegisterAccountResponse
{
    public required string AccessToken { get; init; }
}

public sealed class RegisterAccountHandler
{
    private readonly INewAccountSaver _saver;
    private readonly UtcNow _utcNow;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly GenerateId _generateId;
    private readonly IValidator<RegisterAccount> _validator;
    private readonly IAuthenticationService _authenticationService;

    public RegisterAccountHandler(INewAccountSaver saver, UtcNow utcNow, IPasswordHasher passwordHasher,
        IEmailVerificationManager emailVerificationManager, GenerateId generateId,
        IValidator<RegisterAccount> validator, IAuthenticationService authenticationService)
    {
        _saver = saver;
        _utcNow = utcNow;
        _passwordHasher = passwordHasher;
        _emailVerificationManager = emailVerificationManager;
        _generateId = generateId;
        _validator = validator;
        _authenticationService = authenticationService;
    }

    public async Task<Result<RegisterAccountResponse>> Handle(RegisterAccount req, CancellationToken ct = default)
    {
        var validationResult = await _validator.ValidateAsync(req, ct);

        if (!validationResult.IsValid)
        {
            return validationResult.ToErrorResult();
        }

        var hashedPassword = _passwordHasher.Hash(req.Password);
        var accountId = await _generateId();
        var account = Account.CreateNewAccount(accountId, req.Email, hashedPassword, req.Email, _utcNow());

        await _saver.Save(account);

        await _emailVerificationManager.SendCode(accountId, req.Email);

        return (await _authenticationService.LogIn(req.Email, req.Password, req.Fingerprint, ct))
            .Map(accessToken => new RegisterAccountResponse { AccessToken = accessToken });
    }
}

public interface INewAccountSaver
{
    Task Save(Account account);
}

public class NewAccountSaver : INewAccountSaver
{
    private readonly IDbConnection _dbConnection;

    public NewAccountSaver(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Save(Account account)
    {
        await _dbConnection.ExecuteAsync(
            "INSERT INTO iam.identity (id, username, password_hash, email, created_at, updated_at) VALUES (@Id, @Username, @PasswordHash, @Email, @CreatedAt, @UpdatedAt)",
            new
            {
                account.Id,
                account.Username,
                account.PasswordHash,
                account.Email,
                account.CreatedAt,
                account.UpdatedAt,
            });
    }
}