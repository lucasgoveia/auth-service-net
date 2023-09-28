using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Fakes;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class InitiateEmailVerificationTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    
    public InitiateEmailVerificationTests(IntegrationTestFactory factory) : base(factory)
    {
    }
    
    protected override async Task Seed()
    {
        await base.Seed();
        var registerAccountRequest = new RegisterAccount
        {
            Email = TestEmail,
            Password = "Test1234!_345ax1",
        };

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
        res.EnsureSuccessStatusCode();
        
        res = await Client.PostAsJsonAsync("/login", new Login
        {
            Password = registerAccountRequest.Password,
            Username = registerAccountRequest.Email,
            RememberMe = true,
        });
        
        var accessToken = (await res.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken;
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        await ((FakeMessageBus)MessageBus).Reset();
    }
    
    [Fact]
    public async Task Initiate_email_verification_should_send_email_verification()
    {
        // Act
        await Client.PostAsync("accounts/initiate-email-verification", null!);

        // Assert
        ((FakeMessageBus)MessageBus).Messages.Should().Contain(x =>
            x is SendEmailVerification && ((SendEmailVerification)x).Email == TestEmail);
    }
    
    [Fact]
    public async Task Initiate_email_verification_should_return_unauthorized_when_not_authenticated()
    {
        //Arrange
        Client.DefaultRequestHeaders.Authorization = null;
        
        // Act
        var res = await Client.PostAsync("accounts/initiate-email-verification", null!);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
    
    [Fact]
    public async Task Initiate_email_verification_should_be_successful_when_authenticated()
    {
        //Arrange
        // Act
        var res = await Client.PostAsync("accounts/initiate-email-verification", null!);

        // Assert
        res.Should().BeSuccessful();
    }

}