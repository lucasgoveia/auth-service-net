using System.Data;
using AuthService.Common.Consts;
using AuthService.EmailTemplating;
using AuthService.Mailing;
using AuthService.WebApi.Messages.Commands;
using Dapper;
using MassTransit;

namespace AuthService.Consumers.CommandHandlers;

public class SendPasswordRecoveryConsumer(IEmailSender emailSender, IDbConnection dbConnection) : IConsumer<SendPasswordRecovery>
{
    public async Task Consume(ConsumeContext<SendPasswordRecovery> context)
    {
        var template = TemplateEmailFinder.GetTemplate(Templates.PasswordRecovery);

        var username = await dbConnection.QuerySingleOrDefaultAsync<string>(
            $@"SELECT u.name FROM {TableNames.Users} u 
                    JOIN {TableNames.UserEmails} e ON u.id = e.user_id
                    WHERE e.email = @Email",
            new { context.Message.Email });

        if (string.IsNullOrEmpty(username)) return;

        var data = new
        {
            code = context.Message.Code.ToCharArray(), username,
            codeExpirationMinutes = context.Message.CodeExpirationMinutes
        };
        var (subject, body) = template.Render(data);
        await emailSender.SendEmail(subject, body, context.Message.Email);
    }
}