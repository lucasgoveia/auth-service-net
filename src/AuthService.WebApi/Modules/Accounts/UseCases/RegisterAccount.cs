using System.Data;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Consts;
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
        var identityId = await _generateId();
        var account = Identity.CreateNewIdentity(identityId, req.Email, hashedPassword, req.Email, _utcNow());

        await _saver.Save(account);

        await _emailVerificationManager.SendCode(identityId, req.Email);

        var accessToken = await _authenticationService.Authenticate(identityId, ct);
        return SuccessResult.Success(new RegisterAccountResponse { AccessToken = accessToken });
    }
}

public interface INewAccountSaver
{
    Task Save(Identity identity);
}

public class NewAccountSaver : INewAccountSaver
{
    private readonly IDbConnection _dbConnection;

    public NewAccountSaver(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Save(Identity identity)
    {
        await _dbConnection.ExecuteAsync(
            $"INSERT INTO {TableNames.Identities} (id, username, password_hash, email, created_at, updated_at) VALUES (@Id, @Username, @PasswordHash, @Email, @CreatedAt, @UpdatedAt)",
            new
            {
                identity.Id,
                identity.Username,
                identity.PasswordHash,
                identity.Email,
                identity.CreatedAt,
                identity.UpdatedAt,
            });
    }
}