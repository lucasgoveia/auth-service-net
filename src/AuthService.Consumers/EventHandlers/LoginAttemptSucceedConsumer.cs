using System.Data;
using AuthService.Common.Consts;
using AuthService.WebApi.Messages.Events;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.EventHandlers;

public class LoginAttemptSucceedConsumer : IConsumer<LoginAttemptSucceed>
{
    private readonly IDbConnection _dbConnection;

    public LoginAttemptSucceedConsumer(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Consume(ConsumeContext<LoginAttemptSucceed> context)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET access_failed_count = 0, lockout_end_date = NULL WHERE id = @UserId",
            new { context.Message.UserId });
    }
}