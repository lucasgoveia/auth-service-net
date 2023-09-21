using System.Data;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Results;
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
    private readonly IIdentityEmailGetter _identityEmailGetter;
    private readonly ISessionManager _sessionManager;

    public InitiateEmailVerificationHandler(IEmailVerificationManager emailVerificationManager, ISessionManager sessionManager,
        IIdentityEmailGetter identityEmailGetter)
    {
        _emailVerificationManager = emailVerificationManager;
        _sessionManager = sessionManager;
        _identityEmailGetter = identityEmailGetter;
    }

    public async Task<Result> Handle(InitiateEmailVerification req, CancellationToken ct = default)
    {
        var identityId = _sessionManager.IdentityId;

        if (!identityId.HasValue)
        {
            throw new InvalidOperationException();
        }

        var email = await _identityEmailGetter.Get(identityId.Value, ct);
        await _emailVerificationManager.SendCode(identityId.Value, email);

        return SuccessResult.Success();
    }
}

public interface IIdentityEmailGetter
{
    Task<string> Get(long identityId, CancellationToken ct = default);
}

public class IdentityEmailGetter : IIdentityEmailGetter
{
    private readonly IDbConnection _dbConnection;

    public IdentityEmailGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task<string> Get(long identityId, CancellationToken ct = default)
    {
        return await _dbConnection.QuerySingleAsync<string>(
            $"SELECT email FROM {TableNames.Identities} WHERE Id = @identityId", new { identityId });
    }
}