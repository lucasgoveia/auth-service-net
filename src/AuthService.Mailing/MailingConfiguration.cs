using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthService.Mailing;

public static class MailingConfiguration
{
    public static void AddMailingSetup(this IHostBuilder hostBuilder)
    {
        hostBuilder.ConfigureServices((context, services) =>
        {
            services.AddSingleton<IEmailSender, EmailSender>();
            services.Configure<SmtpConfig>(context.Configuration.GetSection("SmtpConfiguration"));
            services.Configure<MailConfig>(context.Configuration.GetSection("MailConfiguration"));
        });
    }
}