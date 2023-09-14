using System.Data;
using Dapper;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IUsernameAvailabilityChecker
{
    Task<bool> IsAvailable(string username, CancellationToken cancellationToken = default);
}

public class UsernameAvailabilityChecker : IUsernameAvailabilityChecker
{
    private readonly IDbConnection _dbConnection;

    public UsernameAvailabilityChecker(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task<bool> IsAvailable(string username, CancellationToken cancellationToken = default)
    {
        var count = await _dbConnection.QuerySingleAsync<int>(
            "SELECT COUNT(*) FROM iam.identity WHERE LOWER(username) = @Username", new { Username = username.ToLower() });
        return count == 0;
    }
}