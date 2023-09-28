using System.Data;
using AuthService.Common.Consts;
using AuthService.EmailTemplating;
using AuthService.Mailing;
using AuthService.WebApi.Messages.Commands;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.CommandHandlers;

public class SendPasswordRecoveryConsumer : IConsumer<SendPasswordRecovery>
{
    private readonly IEmailSender _emailSender;
    private readonly IDbConnection _dbConnection;

    public SendPasswordRecoveryConsumer(IEmailSender emailSender, IDbConnection dbConnection)
    {
        _emailSender = emailSender;
        _dbConnection = dbConnection;
    }

    public async Task Consume(ConsumeContext<SendPasswordRecovery> context)
    {
        var template = TemplateEmailFinder.GetTemplate(Templates.PasswordRecovery);

        var username = await _dbConnection.QuerySingleOrDefaultAsync<string>(
            $"SELECT name FROM {TableNames.Users} WHERE email = @Email",
            new { context.Message.Email });

        if (string.IsNullOrEmpty(username)) return;

        var data = new
        {
            code = context.Message.Code.ToCharArray(), username,
            codeExpirationMinutes = context.Message.CodeExpirationMinutes
        };
        var (subject, body) = template.Render(data);
        await _emailSender.SendEmail(subject, body, context.Message.Email);
    }
}