using System.Data;
using AuthService.Common.Consts;
using Dapper;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface ICredentialAvailabilityChecker
{
    Task<bool> IsEmailAvailable(string email, CancellationToken cancellationToken = default);
}

public class CredentialAvailabilityChecker(IDbConnection dbConnection) : ICredentialAvailabilityChecker
{
    public async Task<bool> IsEmailAvailable(string email, CancellationToken cancellationToken = default)
    {
        var count = await dbConnection.QuerySingleAsync<int>(
            $"SELECT COUNT(*) FROM {TableNames.Credentials} WHERE identifier = @Email",
            new { Email = email.ToLower() });
        return count == 0;
    }
}