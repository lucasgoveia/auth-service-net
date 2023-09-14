using AuthService.Consumers.CommandHandlers;
using MassTransit;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Consumers.Configurations;

public static class BusConfiguration
{
    public static void AddBusSetup(this IServiceCollection services)
    {
        services.AddMassTransit(bus =>
        {
            bus.SetKebabCaseEndpointNameFormatter();

            bus.AddConsumer<SendEmailVerificationConsumer>();

            bus.UsingAmazonSqs((context, cfg) =>
            {
                cfg.Host("sa-east-1", h =>
                {
                    h.AccessKey("");
                    h.SecretKey("");
                });

                cfg.ConfigureEndpoints(context);
            });
        });
    }
}