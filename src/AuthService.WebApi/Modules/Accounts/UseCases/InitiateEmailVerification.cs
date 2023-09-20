using System.Data;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Modules.Accounts.Functionality;
using Dapper;
using ISession = AuthService.WebApi.Common.ISession;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public class InitiateEmailVerificationHandler
{
    private readonly IEmailVerificationManager _emailVerificationManager;
    private readonly IIdentityEmailGetter _identityEmailGetter;
    private readonly ISession _session;

    public InitiateEmailVerificationHandler(IEmailVerificationManager emailVerificationManager, ISession session,
        IIdentityEmailGetter identityEmailGetter)
    {
        _emailVerificationManager = emailVerificationManager;
        _session = session;
        _identityEmailGetter = identityEmailGetter;
    }

    public async Task<Result> Handle(CancellationToken ct = default)
    {
        var identityId = _session.IdentityId;

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