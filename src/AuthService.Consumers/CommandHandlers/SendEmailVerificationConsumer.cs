using System.Text.Json;
using AuthService.EmailTemplating;
using AuthService.Mailing;
using AuthService.WebApi.Messages.Commands;
using MassTransit;
using Microsoft.Extensions.Logging;

namespace AuthService.Consumers.CommandHandlers;

public class SendEmailVerificationConsumer(ILogger<SendEmailVerificationConsumer> logger, IEmailSender emailSender)
    : IConsumer<SendEmailVerification>
{
    public async Task Consume(ConsumeContext<SendEmailVerification> context)
    {
        logger.LogInformation("Sending email verification code to {Email}", context.Message.Email);

        var template = TemplateEmailFinder.GetTemplate(Templates.EmailVerification);
        var (subject, body) = template.Render(new { code = context.Message.Code.ToCharArray()});

        await emailSender.SendEmail(subject, body, context.Message.Email);
    }
}