using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Utils;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class ChangePasswordTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    private const string TestPassword = "Test1234!_345ax1";

    public ChangePasswordTests(IntegrationTestFactory factory) : base(factory)
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

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        var accessToken = (await res.Content.ReadFromJsonAsync<RegisterAccountResponse>())!.AccessToken;
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }

    [Fact]
    public async Task Change_password_with_valid_credentials_should_be_success()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Change_password_with_invalid_credentials_should_return_unauthorized()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = "invalid",
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Change_password_with_weak_password_should_return_bad_request()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "test",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Change_password_should_not_allow_same_password()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = TestPassword,
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Change_password_as_not_authenticated_user_should_return_unauthorized()
    {
        // Arrange
        Client.DefaultRequestHeaders.Authorization = null;
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Change_password_should_not_allow_login_with_old_password()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);
        await Client.PostAsync("/logout", null!);

        var res = await Client.PostAsJsonAsync("/login", new Login
        {
            Username = TestEmail,
            Password = TestPassword,
            RememberMe = false,
        });

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Change_password_should_login_with_new_password()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);
        await Client.PostAsync("/logout", null!);

        var res = await Client.PostAsJsonAsync("/login", new Login
        {
            Username = TestEmail,
            Password = "Test1234!_345ax2",
            RememberMe = false,
        });

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Change_password_should_issue_new_access_token()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);
        var accessToken = (await res.Content.ReadFromJsonAsync<ChangePasswordResponse>())!.AccessToken;

        // Assert
        accessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Change_password_should_issue_new_refresh_token()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = false
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        var refreshCookie =
            res.GetCookies().FirstOrDefault(x => x.Name == AuthenticationService.RefreshTokenCookieName);

        refreshCookie.Should().NotBeNull();
        refreshCookie!.Value.Should().NotBeNullOrEmpty();
        refreshCookie.Expires.Should()
            .Be(DateTimeHolder.MockedUtcNow.Add(
                TimeSpan.FromHours(JwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)));
    }
    
    // TODO: Test LogOutAllSessions
}