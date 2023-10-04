using System.Net;
using System.Security.Authentication;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthService.Mailing;

public interface IEmailSender
{
    Task SendEmail(string subject, string body, string recipient);
}

public class EmailSender(IOptions<SmtpConfig> config, IOptions<MailConfig> mailConfig)
    : IEmailSender
{
    private readonly SmtpConfig _config = config.Value;
    private readonly MailConfig _mailConfig = mailConfig.Value;

    public async Task SendEmail(string subject, string body, string recipient)
    {
        var smtpClient = new SmtpClient();
        
        
        await smtpClient.ConnectAsync(_config.Host, _config.Port);
        
        var credentials = new NetworkCredential(_config.UserName, _config.Password);
        
        smtpClient.SslProtocols = _config.EnableSsl switch
        {
            true => SslProtocols.Tls12,
            _ => SslProtocols.None
        };
        
        if (!_config.UseDefaultCredentials)
        {
            await smtpClient.AuthenticateAsync(credentials);
        }
        
        var message = new MimeMessage();
        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = body,
            TextBody = "-"
        }; 
        
        message.Body = bodyBuilder.ToMessageBody();
        message.Subject = subject;

        message.To.Add(new MailboxAddress(recipient, recipient));
        
        message.From.Add(new MailboxAddress(_mailConfig.FromName, _mailConfig.FromEmail));
        
        await smtpClient.SendAsync(message);
    }
}