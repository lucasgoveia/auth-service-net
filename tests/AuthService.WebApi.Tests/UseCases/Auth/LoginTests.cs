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

        var req = new RegisterAccount
        {
            Email = TestEmail,
            Password = TestPassword,
        };

        await Client.PostAsJsonAsync("/accounts/register", req);
    }

    [Fact]
    public async Task Login_with_valid_credentials_should_be_success()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = TestPassword,
            RememberMe = false,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Login_with_valid_credentials_should_return_access_token()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = TestPassword,
            RememberMe = false,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        var resBody = await res.Content.ReadFromJsonAsync<LoginResponse>();
        resBody!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_with_invalid_password_should_return_unauthorized()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = "INVALID_PASSWORD",
            RememberMe = false,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_with_not_existing_username_should_return_unauthorized()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = "some_other_email@example.com",
            Password = TestPassword,
            RememberMe = false,
        };

        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
    
    [Fact]
    public async Task Login_3_times_with_invalid_password_should_lockout_account()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = "WRONG_PASSWORD",
            RememberMe = false,
        };
            
        for (int _ = 0; _ < 3; _++)
        {
            
            await Client.PostAsJsonAsync("/login", loginReq);
        }

        loginReq = loginReq with { Password = TestPassword };
        
        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
    
    [Fact]
    public async Task Login_should_allow_after_lockout_end()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = "WRONG_PASSWORD",
            RememberMe = false,
        };
            
        for (int _ = 0; _ < 3; _++)
        {
            
            await Client.PostAsJsonAsync("/login", loginReq);
        }

        DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(6);

        loginReq = loginReq with { Password = TestPassword };
        
        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.OK);
    }
    
    [Fact]
    public async Task Login_lockout_should_increment_with_failed_attempts()
    {
        // Arrange
        var loginReq = new Login
        {
            Username = TestEmail,
            Password = "WRONG_PASSWORD",
            RememberMe = false,
        };
            
        for (int _ = 0; _ < 3; _++)
        {
            
            await Client.PostAsJsonAsync("/login", loginReq);
        }

        DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(6);

        await Client.PostAsJsonAsync("/login", loginReq);;
        
        loginReq = loginReq with { Password = TestPassword };
        
        DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(6);
        
        // Act
        var res = await Client.PostAsJsonAsync("/login", loginReq);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}