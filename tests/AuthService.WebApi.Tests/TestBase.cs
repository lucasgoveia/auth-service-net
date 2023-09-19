using AuthService.Mailing;
using AuthService.WebApi.Common.Messaging;
using AuthService.WebApi.Tests.Fakes;

namespace AuthService.WebApi.Tests;

public class TestBase : IAsyncLifetime 
{
    protected readonly HttpClient Client;
    protected readonly IntegrationTestFactory Factory;
    protected IMessageBus MessageBus => Factory.MessageBus;
    protected IEmailSender EmailSender => Factory.EmailSender;
    
    protected TestBase(IntegrationTestFactory factory)
    {
        Factory = factory;
        Client = factory.CreateClient();
    }
    
    protected virtual Task Seed() => Task.CompletedTask;
    
    public async Task InitializeAsync()
    {
        await Seed();
    }

    public async Task DisposeAsync()
    {
        await Factory.ResetDatabaseAsync();
        await Factory.ResetCacheAsync();
        await Factory.ResetBusAsync();
    }
}