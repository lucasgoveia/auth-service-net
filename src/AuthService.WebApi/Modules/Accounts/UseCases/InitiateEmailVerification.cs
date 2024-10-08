using System.Data;
using AuthService.Common.Consts;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record InitiateEmailVerification
{
    public static readonly InitiateEmailVerification Instance = new();
}

public class InitiateEmailVerificationHandler(
    IEmailVerificationManager emailVerificationManager,
    ISessionManager sessionManager,
    IUserEmailGetter userEmailGetter)
{
    public async Task<Result> Handle(InitiateEmailVerification req, CancellationToken ct = default)
    {
        var userId = sessionManager.UserId!.Value;

        var email = await userEmailGetter.Get(userId, ct);
        await emailVerificationManager.SendCode(userId, email);

        return Result.Accepted();
    }
}

public interface IUserEmailGetter
{
    Task<string> Get(SnowflakeId userId, CancellationToken ct = default);
}

public class UserEmailGetter(IDbConnection dbConnection) : IUserEmailGetter
{
    public async Task<string> Get(SnowflakeId userId, CancellationToken ct = default)
    {
        return await dbConnection.QuerySingleAsync<string>(
            $"SELECT email FROM {TableNames.UserEmails} WHERE user_id = @userId", new { userId });
    }
}