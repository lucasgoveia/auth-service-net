using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Mailing;

public static class MailingConfiguration
{
    public static IServiceCollection AddMailingSetup(this IServiceCollection services, BasicAWSCredentials credentials)
    {
        var sesConfig = new AmazonSimpleEmailServiceConfig { RegionEndpoint = RegionEndpoint.SAEast1 };

        services.AddSingleton<IAmazonSimpleEmailService>(
            _ => new AmazonSimpleEmailServiceClient(credentials, sesConfig));

        services.AddSingleton<IEmailSender, EmailSender>();

        return services;
    }
}