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
    IAuthenticationService authenticationService, IDbConnection dbConnection)
{
    public async Task<Result> Handle(InitiatePasswordRecovery request, CancellationToken ct)
    {
        var info = await dbConnection.QuerySingleOrDefaultAsync<(long userId, long identityId)?>(
            $"SELECT user_id, id FROM {TableNames.Identities} WHERE username = @Email", request);

        if (!info.HasValue)
            return SuccessResult.Success();

        var (userId, identityId) = info.Value;
        
        await passwordRecoveryManager.SendCode(userId, request.Email);
        await authenticationService.AuthenticateLimited(userId, identityId, ct);
        return SuccessResult.Success();
    }
}