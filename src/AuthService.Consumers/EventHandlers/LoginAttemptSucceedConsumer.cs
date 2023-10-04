using System.Data;
using AuthService.Common.Consts;
using AuthService.WebApi.Messages.Events;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.EventHandlers;

public class LoginAttemptSucceedConsumer(IDbConnection dbConnection) : IConsumer<LoginAttemptSucceed>
{
    public async Task Consume(ConsumeContext<LoginAttemptSucceed> context)
    {
        await dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET access_failed_count = 0, lockout_end_date = NULL WHERE id = @UserId",
            new { context.Message.UserId });
    }
}