using AuthService.Common.Messaging;
using AuthService.Consumers.CommandHandlers;
using AuthService.Consumers.EventHandlers;
using AuthService.WebApi.Messages.Commands;
using MassTransit;

namespace AuthService.WebApi.Configurations;

public static class BusConfiguration
{
    public static void AddBusSetup(this WebApplicationBuilder builder)
    {
        builder.Services.AddScoped<IMessageBus, MessageBus>();
        builder.Services.AddMassTransit(bus =>
        {
            bus.SetKebabCaseEndpointNameFormatter();

            bus.AddConsumer<SendEmailVerificationConsumer>();
            bus.AddConsumer<SendPasswordRecoveryConsumer>();
            
            bus.AddConsumer<LoginAttemptFailedConsumer>();
            bus.AddConsumer<LoginAttemptSucceedConsumer>();

            bus.UsingRabbitMq((context, cfg) =>
            {
                cfg.Host(builder.Configuration.GetConnectionString("Amqp"));

                cfg.ConfigureEndpoints(context);
            });
        });
    }
}