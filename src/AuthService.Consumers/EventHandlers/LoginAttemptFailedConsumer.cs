using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Messages.Events;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.EventHandlers;

public class LoginAttemptFailedConsumer(IDbConnection dbConnection, UtcNow utcNow) : IConsumer<LoginAttemptFailed>
{
    public async Task Consume(ConsumeContext<LoginAttemptFailed> context)
    {
        var failedAccess = await dbConnection.QuerySingleAsync<int>(
            $"SELECT access_failed_count + 1 FROM {TableNames.Users} WHERE id = @UserId",
            new { context.Message.UserId });
        
        var lockoutEndDate = failedAccess > 2
            ? utcNow() + TimeSpan.FromMinutes(Math.Pow(5, failedAccess - 2))
            : (DateTime?)null;

        await dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET access_failed_count = @FailedAccess, lockout_end_date = @LockoutEnd WHERE id = @UserId",
            new { FailedAccess = failedAccess, LockoutEnd = lockoutEndDate, context.Message.UserId });
    }
}