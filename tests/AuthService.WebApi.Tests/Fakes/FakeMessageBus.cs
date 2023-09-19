using AuthService.WebApi.Common.Messaging;
using MassTransit;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace AuthService.WebApi.Tests.Fakes;

public class FakeMessageBus : IMessageBus
{
    private readonly IServiceProvider _serviceProvider;
    public List<object> Messages { get; private set; } = new();

    public FakeMessageBus(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task Publish<T>(T entity, CancellationToken ct) where T : class
    {
        Messages.Add(entity);  
        var consumer = _serviceProvider.GetService<IConsumer<T>>();
        
        if (consumer == null) return;

        var context = Substitute.For<ConsumeContext<T>>();
        context.Message.Returns(entity);
        context.MessageId.Returns(NewId.NextSequentialGuid());
        await consumer.Consume(context);
    }

    public async Task PublishBatch<T>(IEnumerable<T> entities) where T : class
    {
        var entitiesList = entities.ToList();
        Messages.AddRange(entitiesList);

        var consumer = _serviceProvider.GetService<IConsumer<T>>();
        if (consumer == null) return;

        var context = Substitute.For<ConsumeContext<T>>();

        foreach (var e in entitiesList)
        {
            context.Message.Returns(e);
            context.MessageId.Returns(NewId.NextSequentialGuid());
            await consumer.Consume(context);
        }
    }

    public Task Reset()
    {
        Messages.Clear();
        return Task.CompletedTask;
    }
}