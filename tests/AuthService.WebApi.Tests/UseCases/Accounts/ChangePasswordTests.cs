using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Utils;
using FluentAssertions;
using Microsoft.Net.Http.Headers;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class ChangePasswordTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    private const string TestPassword = "Test1234!_345ax1";
    private string _accessToken = null!;
    private string[] _cookies = null!;

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
            Name = "Test User"
        };

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
        res.EnsureSuccessStatusCode();

        res = await Client.PostAsJsonAsync("/login", new Login
        {
            Password = TestPassword,
            Username = TestEmail,
            RememberMe = true,
        });

        _accessToken = (await res.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken;
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

        _cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
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
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);
        res.EnsureSuccessStatusCode();
        res = await Client.PostAsync("/logout", null!);
        res.EnsureSuccessStatusCode();

        res = await Client.PostAsJsonAsync("/login", new Login
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
            res.GetCookies().FirstOrDefault(x => x.Name == AuthCookieNames.RefreshTokenCookieName);

        refreshCookie.Should().NotBeNull();
        refreshCookie!.Value.Should().NotBeNullOrEmpty();
        refreshCookie.Expires.Should()
            .Be(DateTimeHolder.MockedUtcNow.Add(
                TimeSpan.FromHours(JwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)));
    }

    [Fact]
    public async Task Change_password_with_logout_all_sessions_options_should_logout_all_other_devices()
    {
        // Arrange
        var otherSessionsRefreshToken = new List<string[]>(capacity: 5);
        for (var i = 0; i < 5; ++i)
        {
            Client.DefaultRequestHeaders.Authorization = null;
            var fingerprint = Guid.NewGuid().ToString();
            Client.DefaultRequestHeaders.Add("Fingerprint", fingerprint);

            var res = Client.PostAsJsonAsync("/login", new Login
            {
                Username = TestEmail,
                Password = TestPassword,
                RememberMe = true,
            }).GetAwaiter().GetResult();

            otherSessionsRefreshToken.Add(res.Headers.GetValues(HeaderNames.SetCookie).ToArray());
        }
        
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = true
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);

        // Assert
        foreach (var refreshCookie in otherSessionsRefreshToken)
        {
            // Other sessions refresh token should be revoked
            Client.DefaultRequestHeaders.Add("Cookie", refreshCookie);
            var res = await Client.PostAsync("/token", null!);
            res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
        }
    }

    [Fact]
    public async Task Change_password_with_logout_all_sessions_options_should_maintain_the_response_session_active()
    {
        // Arrange
        var changePasswordRequest = new ChangePassword
        {
            CurrentPassword = TestPassword,
            NewPassword = "Test1234!_345ax2",
            LogOutAllSessions = true
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/change-password", changePasswordRequest);
        var cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();

        // Assert
        Client.DefaultRequestHeaders.Add("Cookie", cookies);
        var refreshRes = await Client.PostAsync("/token", null!);
        refreshRes.Should().BeSuccessful();
    }
}