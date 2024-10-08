using System.Data;
using System.Text;
using AuthService.Common.Consts;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record RegisterAccount
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string? Name { get; init; }
}

public record RegisterAccountResponse
{
    public required string AccessToken { get; init; }
}

public class RegisterAccountValidator : AbstractValidator<RegisterAccount>
{
    public RegisterAccountValidator(ICredentialAvailabilityChecker checker, IPasswordPolicy passwordPolicy)
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .MustAsync(async (e, ct) => await checker.IsEmailAvailable(e, ct));

        RuleFor(x => x.Password)
            .NotEmpty()
            .MustAsync(async (p, ct) => await passwordPolicy.IsValid(p));

        RuleFor(x => x.Name)
            .NotEmpty()
            .MinimumLength(2);
    }
}

public sealed class RegisterAccountHandler(
    INewAccountSaver saver,
    UtcNow utcNow,
    IPasswordHasher passwordHasher,
    IEmailVerificationManager emailVerificationManager,
    IAuthenticationService authenticationService)
{
    public async Task<Result<RegisterAccountResponse>> Handle(RegisterAccount req, CancellationToken ct = default)
    {
        var hashedPassword = passwordHasher.Hash(req.Password);
        var identityId = SnowflakeId.NewId();
        var userId = SnowflakeId.NewId();

        var credential = EmailPasswordCredential.Create(userId, identityId, req.Email, hashedPassword, utcNow());
        var user = User.CreateNewUser(userId, req.Name, req.Email, utcNow());

        await saver.Save(user, credential.ToCredentialData());

        await emailVerificationManager.SendCode(userId, req.Email);

        var token = await authenticationService.Authenticate(userId, identityId, true, ct);

        return Result.Created(new RegisterAccountResponse { AccessToken = token });
    }
}

public interface INewAccountSaver
{
    Task Save(User user, CredentialData credential, CancellationToken ct = default);
}

public class NewAccountSaver(IDbConnection dbConnection) : INewAccountSaver
{
    public async Task Save(User user, CredentialData credential, CancellationToken ct = default)
    {
        if (dbConnection.State != ConnectionState.Open)
        {
            dbConnection.Open();
        }

        using var transaction = dbConnection.BeginTransaction();

        await dbConnection.ExecuteAsync(
            $"INSERT INTO {TableNames.Users} (id, name, created_at, updated_at) VALUES (@Id, @Name, @CreatedAt, @UpdatedAt)",
            user);

        await dbConnection.ExecuteAsync(
            $"""
             INSERT INTO {TableNames.Credentials} (id, user_id, type, identifier, secret, provider, verified, created_at, updated_at, deleted_at) 
                             VALUES (@Id, @UserId, @Type::iam.credential_type, @Identifier, @Secret, @Provider, @Verified, @CreatedAt, @UpdatedAt, @DeletedAt)
             """,
            new
            {
                credential.Id,
                credential.UserId,
                Type =credential.Type.ToDbValue(),
                credential.Identifier,
                credential.Secret,
                credential.Provider,
                credential.Verified,
                credential.CreatedAt,
                credential.UpdatedAt,
                credential.DeletedAt
            });

        await InsertEmails(dbConnection, user, transaction, ct);

        transaction.Commit();
    }
    
    private static async Task InsertEmails(IDbConnection conn, User user, IDbTransaction transaction, CancellationToken ct)
    {
        var insertEmailsSql = new StringBuilder($"INSERT INTO {TableNames.UserEmails} (user_id, email, verified, created_at, updated_at) VALUES");
        var parameters = new DynamicParameters();
        
        var valueList = new List<string>();
        
        for(var i = 0; i < user.UserEmails.Count; i++)
        {
            var email = user.UserEmails[i];
            valueList.Add($"(@UserId{i}, @Email{i}, @Verified{i}, @CreatedAt{i}, @UpdatedAt{i})");
            parameters.Add($"UserId{i}", email.UserId);
            parameters.Add($"Email{i}", email.Email);
            parameters.Add($"Verified{i}", email.Verified);
            parameters.Add($"CreatedAt{i}", email.CreatedAt);
            parameters.Add($"UpdatedAt{i}", email.UpdatedAt);
        }
        
        insertEmailsSql.AppendJoin(',', valueList);
        
        await conn.ExecuteAsync(new CommandDefinition(insertEmailsSql.ToString(), parameters, transaction, cancellationToken: ct));
    }
}