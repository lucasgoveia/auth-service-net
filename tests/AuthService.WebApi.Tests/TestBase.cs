using AuthService.Common.Messaging;
using AuthService.Mailing;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Tests.Fakes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthService.WebApi.Tests;

public abstract class TestBase : IAsyncLifetime
{
    protected readonly HttpClient Client;
    protected readonly IntegrationTestFactory Factory;
    protected FakeMessageBus MessageBus => (FakeMessageBus)Factory.MessageBus;
    protected IEmailSender EmailSender => Factory.EmailSender;
    protected FakeServerDateTimeHolder DateTimeHolder => Factory.DateTimeHolder;
    protected JwtConfig JwtConfig => Factory.Services.GetRequiredService<IOptions<JwtConfig>>().Value;

    public TestBase(IntegrationTestFactory factory)
    {
        Factory = factory;
        Client = factory.CreateClient();
    }

    protected virtual Task Seed() => Task.CompletedTask;

    public async Task InitializeAsync()
    {
        await Factory.ResetDatabaseAsync();
        await Factory.ResetCacheAsync();
        await Factory.ResetBusAsync();
        await Seed();
    }

    public Task DisposeAsync()
    {
        return Task.CompletedTask;
    }
}