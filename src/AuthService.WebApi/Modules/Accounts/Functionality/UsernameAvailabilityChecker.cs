using System.Data;
using AuthService.Common.Consts;
using Dapper;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IUsernameAvailabilityChecker
{
    Task<bool> IsAvailable(string username, CancellationToken cancellationToken = default);
}

public class UsernameAvailabilityChecker(IDbConnection dbConnection) : IUsernameAvailabilityChecker
{
    public async Task<bool> IsAvailable(string username, CancellationToken cancellationToken = default)
    {
        var count = await dbConnection.QuerySingleAsync<int>(
            $"SELECT COUNT(*) FROM {TableNames.Identities} WHERE LOWER(username) = @Username",
            new { Username = username.ToLower() });
        return count == 0;
    }
}