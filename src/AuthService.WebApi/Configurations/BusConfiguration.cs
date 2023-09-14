using AuthService.Consumers.CommandHandlers;
using MassTransit;

namespace AuthService.WebApi.Configurations;

public static class BusConfiguration
{
    public static void AddBusSetup(this WebApplicationBuilder builder)
    {
        builder.Services.AddMassTransit(bus =>
        {
            bus.SetKebabCaseEndpointNameFormatter();

            bus.AddConsumer<SendEmailVerificationConsumer>();

            bus.UsingAmazonSqs((context, cfg) =>
            {
                cfg.Host("sa-east-1", h =>
                {
                    h.AccessKey(builder.Configuration.GetValue<string>("aws_access_key_id"));
                    h.SecretKey(builder.Configuration.GetValue<string>("aws_secret_access_key"));
                });

                cfg.ConfigureEndpoints(context);
            });
        });
    }
}