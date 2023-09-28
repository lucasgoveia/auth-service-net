using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Messages.Events;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.EventHandlers;

public class LoginAttemptFailedConsumer : IConsumer<LoginAttemptFailed>
{
    private readonly IDbConnection _dbConnection;
    private readonly UtcNow _utcNow;

    public LoginAttemptFailedConsumer(IDbConnection dbConnection, UtcNow utcNow)
    {
        _dbConnection = dbConnection;
        _utcNow = utcNow;
    }

    public async Task Consume(ConsumeContext<LoginAttemptFailed> context)
    {
        var failedAccess = await _dbConnection.QuerySingleAsync<int>(
            $"SELECT access_failed_count + 1 FROM {TableNames.Users} WHERE id = @UserId",
            new { context.Message.UserId });
        
        var lockoutEndDate = failedAccess > 2
            ? _utcNow() + TimeSpan.FromMinutes(Math.Pow(5, failedAccess - 2))
            : (DateTime?)null;

        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET access_failed_count = @FailedAccess, lockout_end_date = @LockoutEnd WHERE id = @UserId",
            new { FailedAccess = failedAccess, LockoutEnd = lockoutEndDate, context.Message.UserId });
    }
}