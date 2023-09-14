using System.Text.Json;
using AuthService.EmailTemplating;
using AuthService.Mailing;
using AuthService.Messages.Commands;
using MassTransit;
using Microsoft.Extensions.Logging;

namespace AuthService.Consumers.CommandHandlers;

public class SendEmailVerificationConsumer : IConsumer<SendEmailVerification>
{
    private readonly ILogger<SendEmailVerificationConsumer> _logger;
    private readonly IEmailSender _emailSender;

    public SendEmailVerificationConsumer(ILogger<SendEmailVerificationConsumer> logger, IEmailSender emailSender)
    {
        _logger = logger;
        _emailSender = emailSender;
    }

    public async Task Consume(ConsumeContext<SendEmailVerification> context)
    {
        _logger.LogInformation("Sending email verification code to {Email}", context.Message.Email);

        var template = TemplateEmailFinder.GetTemplate(Templates.EmailVerification);
        var (subject, body) = template.Render(new { code = context.Message.Code.ToCharArray()});

        await _emailSender.SendEmail(subject, body, context.Message.Email);
    }
}