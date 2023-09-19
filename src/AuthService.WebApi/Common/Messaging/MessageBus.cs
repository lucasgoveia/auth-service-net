using MassTransit;

namespace AuthService.WebApi.Common.Messaging;

public interface IMessageBus
{
    Task Publish<T>(T message, CancellationToken cancellationToken = default)
        where T : class;
    Task PublishBatch<T>(IEnumerable<T> entities) where T: class;
}

public class MessageBus : IMessageBus
{
    private readonly IPublishEndpoint _publishEndpoint;

    public MessageBus(IPublishEndpoint publishEndpoint)
    {
        _publishEndpoint = publishEndpoint;
    }

    public async Task Publish<T>(T message, CancellationToken cancellationToken = default) where T : class
    {
        await _publishEndpoint.Publish(message, cancellationToken);
    }

    public async Task PublishBatch<T>(IEnumerable<T> entities) where T : class
    {
        await _publishEndpoint.PublishBatch(entities);
    }
}