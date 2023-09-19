using System.Net;
using System.Net.Http.Json;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Auth;

public class LoginTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    private const string TestPassword = "Test1234!_345ax1";

    public LoginTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    protected override async Task Seed()
    {
        await base.Seed();

        var registerAccountRequest = new RegisterAccount
        {
            Email = TestEmail,
            Password = TestPassword,
        };

        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
    }

    [Fact]
    public async Task Login_with_valid_credentials_should_be_success()
    {
        // Arrange
        var registerAccountRequest = new Login
        {
            Username = TestEmail,
            Password = TestPassword,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", registerAccountRequest);

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Login_with_valid_credentials_should_return_access_token()
    {
        // Arrange
        var registerAccountRequest = new Login
        {
            Username = TestEmail,
            Password = TestPassword,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", registerAccountRequest);

        // Assert
        var resBody = await res.Content.ReadFromJsonAsync<LoginResponse>();
        resBody!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_with_invalid_password_should_return_unauthorized()
    {
        // Arrange
        var registerAccountRequest = new Login
        {
            Username = TestEmail,
            Password = "INVALID_PASSWORD",
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", registerAccountRequest);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_with_not_existing_username_should_return_unauthorized()
    {
        // Arrange
        var registerAccountRequest = new Login
        {
            Username = "some_other_email@example.com",
            Password = TestPassword,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", registerAccountRequest);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}