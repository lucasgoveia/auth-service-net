using MassTransit;

namespace AuthService.Common.Messaging;

public interface IMessageBus
{
    Task Publish<T>(T message, CancellationToken cancellationToken = default)
        where T : class;
    Task PublishBatch<T>(IEnumerable<T> entities) where T: class;
}

public class MessageBus(IPublishEndpoint publishEndpoint) : IMessageBus
{
    public async Task Publish<T>(T message, CancellationToken cancellationToken = default) where T : class
    {
        await publishEndpoint.Publish(message, cancellationToken);
    }

    public async Task PublishBatch<T>(IEnumerable<T> entities) where T : class
    {
        await publishEndpoint.PublishBatch(entities);
    }
}