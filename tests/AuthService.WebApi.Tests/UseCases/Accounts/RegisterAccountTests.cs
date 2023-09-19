using System.Data;
using System.Net;
using System.Net.Http.Json;
using AuthService.Messages.Commands;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Tests.Fakes;
using AuthService.WebApi.Tests.Utils;
using Dapper;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class RegisterAccountTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    public RegisterAccountTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Register_account_with_valid_data_returns_success()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Register_account_with_invalid_email_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test",
            Password = "Test1234!_345ax1",
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_with_weak_password_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "teste@example.com",
            Password = "test",
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_with_existing_email_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_should_return_access_token()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        var resBody = await res.Content.ReadFromJsonAsync<RegisterAccountResponse>();
        resBody!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Register_account_should_set_refresh_token_cookie()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        res.Should().BeSuccessful();
        res.GetCookies().Should().Contain(x => x.Name == AuthenticationService.RefreshTokenCookieName && !string.IsNullOrEmpty(x.Value));
    }

    [Fact]
    public async Task Register_account_should_send_email_verification()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        ((FakeMessageBus)MessageBus).Messages.Should().Contain(x =>
            x is SendEmailVerification && ((SendEmailVerification)x).Email == registerAccountRequest.Email);
    }
    
    [Fact]
    public async Task Register_account_should_save_identity_to_db()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        (await Factory.Services.GetRequiredService<IDbConnection>()
            .QuerySingleOrDefaultAsync<int>($"SELECT COUNT(*) FROM {TableNames.Identities} WHERE username = @Email",
                new { registerAccountRequest.Email }))
            .Should().Be(1);
    }
}