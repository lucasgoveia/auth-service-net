using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Mailing;

public static class MailingConfiguration
{
    public static IServiceCollection AddMailingSetup(this IServiceCollection services)
    {
        services.AddSingleton<IEmailSender, EmailSender>();

        return services;
    }
}