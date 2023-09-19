using System.Net;
using System.Net.Mail;
using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;

namespace AuthService.Mailing;

public interface IEmailSender
{
    Task SendEmail(string subject, string body, string recipient);
}

public class EmailSender : IEmailSender
{
    public async Task SendEmail(string subject, string body, string recipient)
    {
        using var smtpClient = new SmtpClient("localhost", 2525);

        using var mailMessage = new MailMessage();
        mailMessage.From = new MailAddress("no-reply@auth.lucasgoveia.com");
        mailMessage.Subject = subject;
        mailMessage.Body = body;
        mailMessage.IsBodyHtml = true;

        mailMessage.To.Add(recipient);

        await smtpClient.SendMailAsync(mailMessage);
    }
}