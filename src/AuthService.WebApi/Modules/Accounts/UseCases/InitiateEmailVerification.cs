using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record InitiateEmailVerification
{
    public static readonly InitiateEmailVerification Instance = new();
}

public class InitiateEmailVerificationHandler
{
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly IUserEmailGetter _userEmailGetter;
    private readonly ISessionManager _sessionManager;

    public InitiateEmailVerificationHandler(IEmailVerificationManager emailVerificationManager,
        ISessionManager sessionManager,
        IUserEmailGetter userEmailGetter)
    {
        _emailVerificationManager = emailVerificationManager;
        _sessionManager = sessionManager;
        _userEmailGetter = userEmailGetter;
    }

    public async Task<Result> Handle(InitiateEmailVerification req, CancellationToken ct = default)
    {
        var userId = _sessionManager.UserId!.Value;

        var email = await _userEmailGetter.Get(userId, ct);
        await _emailVerificationManager.SendCode(userId, email);

        return SuccessResult.Success();
    }
}

public interface IUserEmailGetter
{
    Task<string> Get(long userId, CancellationToken ct = default);
}

public class UserEmailGetter : IUserEmailGetter
{
    private readonly IDbConnection _dbConnection;

    public UserEmailGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task<string> Get(long userId, CancellationToken ct = default)
    {
        return await _dbConnection.QuerySingleAsync<string>(
            $"SELECT email FROM {TableNames.Users} WHERE Id = @userId", new { userId });
    }
}