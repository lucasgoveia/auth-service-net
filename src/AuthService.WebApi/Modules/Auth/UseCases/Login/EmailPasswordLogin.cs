using System.Data;
using System.Diagnostics;
using AuthService.Common;
using AuthService.Common.Consts;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Messages.Events;
using AuthService.WebApi.Modules.Accounts;
using Dapper;
using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Auth.UseCases.Login;

public record LoginWithEmailNPasswordData
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required bool RememberMe { get; init; }
}

public record LoginWithEmailNPassword
{
    public required LoginWithEmailNPasswordData Body { get; init; }
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public required string RedirectUri { get; init; }
}

public class LoginWithEmailNPasswordDataValidator : AbstractValidator<LoginWithEmailNPasswordData>
{
    public LoginWithEmailNPasswordDataValidator()
    {
        RuleFor(x => x.Email).NotEmpty();
        RuleFor(x => x.Password).NotEmpty();
    }
}

public class LoginWithEmailNPasswordValidator : AbstractValidator<LoginWithEmailNPassword>
{
    public LoginWithEmailNPasswordValidator()
    {
        RuleFor(x => x.Body)
            .NotNull()
            .SetValidator(new LoginWithEmailNPasswordDataValidator());
        RuleFor(x => x.CodeChallenge).NotEmpty();
        RuleFor(x => x.CodeChallengeMethod).NotEmpty();
        RuleFor(x => x.RedirectUri).NotEmpty();
    }
}

public record LoginResponse
{
    public required string Code { get; init; }
}

public class LoginWithEmailNPasswordHandler(
    IMessageBus messageBus,
    UtcNow utcNow,
    ICredentialForLoginGetter credentialForLoginGetter,
    IPasswordHasher passwordHasher,
    PCKEManager pckeManager
)
{
    public async Task<Result<LoginResponse>> Handle(LoginWithEmailNPassword req, CancellationToken ct = default)
    {
        return await ApiActivitySource.Instance.WithActivity<Result<LoginResponse>>(async (activity) =>
        {
            activity?.AddTag("login.type", CredentialType.Email);
            activity?.AddTag("login.identifier", req.Body.Email);
            var credential = await credentialForLoginGetter.GetByEmail(req.Body.Email, utcNow(), ct);
            if (credential is null)
                return Result.Unauthorized();


            var correctCredentials = ApiActivitySource.Instance.WithActivity(
                (_) => passwordHasher.Verify(req.Body.Password, credential.PasswordHash),
                "PasswordVerification");

            if (!correctCredentials)
            {
                activity?.AddEvent(new ActivityEvent("LoginAttemptFailed", utcNow()));
                await messageBus.Publish(new LoginAttemptFailed { UserId = credential.UserId }, ct);
                return Result.Unauthorized();
            }

            activity?.AddEvent(new ActivityEvent("LoginAttemptSuccess", utcNow()));
            var pckeCode = await pckeManager.New(credential.UserId, credential.Id, req.CodeChallenge, req.CodeChallengeMethod, req.RedirectUri, req.Body.RememberMe );

            await messageBus.Publish(new LoginAttemptSucceed { UserId = credential.UserId }, ct);
            return Result.Ok(new LoginResponse { Code = pckeCode});
        });
    }
}

public record SimplePasswordCredential
{
    public required SnowflakeId Id { get; init; }
    public required SnowflakeId UserId { get; init; }
    public required string PasswordHash { get; init; }
}

public interface ICredentialForLoginGetter
{
    Task<SimplePasswordCredential?> GetByEmail(string email, DateTime now, CancellationToken ct = default);
}

public class CredentialForLoginGetter(IDbConnection dbConnection) : ICredentialForLoginGetter
{
    public async Task<SimplePasswordCredential?> GetByEmail(string email, DateTime now, CancellationToken ct = default)
    {
        return await dbConnection.QuerySingleOrDefaultAsync<SimplePasswordCredential>(
            $@"SELECT i.id, i.user_id, i.secret AS PasswordHash 
                FROM {TableNames.Credentials} i
                INNER JOIN {TableNames.Users} u ON i.user_id = u.id
                WHERE i.type = 'email' AND i.identifier = @Email AND u.deleted_at IS NULL 
                    AND i.deleted_at IS NULL 
                    AND (u.lockout_end_date IS NULL OR u.lockout_end_date < @Now)",
            new { Email = email.ToLower(), Now = now });
    }
}