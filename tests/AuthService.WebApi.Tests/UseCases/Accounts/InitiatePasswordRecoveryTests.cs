using System.Net;
using System.Net.Http.Json;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Tests.Fakes;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class InitiatePasswordRecoveryTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    public InitiatePasswordRecoveryTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    protected override async Task Seed()
    {
        await base.Seed();
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
        res.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task InitiatePasswordRecovery_with_valid_email_should_return_ok()
    {
        var response = await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "test@example.com"
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task InitiatePasswordRecovery_with_invalid_email_should_return_bad_request()
    {
        var response = await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "invalid-email"
        });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task InitiatePasswordRecovery_with_unregistered_email_should_return_ok()
    {
        var response = await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "someemail@example.com"
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task InitiatePasswordRecovery_with_unregistered_email_should_not_send_email()
    {
        await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "someemail@example.com"
        });

        ((FakeMessageBus)MessageBus).Messages
            .OfType<SendPasswordRecovery>()
            .Should()
            .BeEmpty();
    }

    [Fact]
    public async Task InitiatePasswordRecovery_with_valid_existing_email_should_send_email()
    {
        await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "test@example.com"
        });
        
        ((FakeMessageBus)MessageBus).Messages
            .OfType<SendPasswordRecovery>()
            .Should()
            .Contain(x => x.Email == "test@example.com");
    }
}