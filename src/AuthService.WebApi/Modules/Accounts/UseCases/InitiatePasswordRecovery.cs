using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using FluentValidation;

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

public class InitiatePasswordRecoveryHandler(IPasswordRecoveryManager passwordRecoveryManager,
    IDbConnection dbConnection)
{
    public async Task<Result> Handle(InitiatePasswordRecovery request, CancellationToken ct)
    {
        var identityExists = await dbConnection.QuerySingleOrDefaultAsync<bool>(
            $"SELECT 1 FROM {TableNames.Identities} WHERE username = @Email", request);

        if (!identityExists)
            return SuccessResult.Success();

        await passwordRecoveryManager.SendCode(request.Email);

        return SuccessResult.Success();
    }
}