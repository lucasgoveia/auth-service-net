using System.Data;
using AuthService.Common.Consts;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;
using LucasGoveia.Results;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record InitiatePasswordRecovery
{
    public required string Email { get; set; }
}

public class InitiatePasswordRecoveryValidator : AbstractValidator<InitiatePasswordRecovery>
{
    public InitiatePasswordRecoveryValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
    }
}

public class InitiatePasswordRecoveryHandler(
    IPasswordRecoveryManager passwordRecoveryManager,
    IDbConnection dbConnection)
{
    public async Task<Result> Handle(InitiatePasswordRecovery request, CancellationToken ct)
    {
        var identityExists = await dbConnection.QuerySingleOrDefaultAsync<bool>(
            $"SELECT 1 FROM {TableNames.Credentials} WHERE identifier = @Email AND type = '{CredentialType.Email.ToDbValue()}'::iam.credential_type", request);

        if (!identityExists)
            return Result.Accepted();

        await passwordRecoveryManager.SendCode(request.Email);

        return Result.Accepted();
    }
}