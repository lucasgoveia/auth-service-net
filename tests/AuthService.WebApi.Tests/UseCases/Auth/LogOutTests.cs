using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AngleSharp.Io;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Utils;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Auth;

public class LogOutTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private string[] _cookies = default!;
    private string _accessToken = default!;

    public LogOutTests(IntegrationTestFactory factory) : base(factory)
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
        
        res = await Client.PostAsJsonAsync("/login", new Login
        {
            Password = registerAccountRequest.Password,
            Username = registerAccountRequest.Email,
            RememberMe = true,
        });
        
        _accessToken = (await res.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken;
        _cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();

        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
    }

    [Fact]
    public async Task LogOut_with_user_logged_in_should_be_success()
    {
        // Act
        var res = await Client.PostAsync("/logout", null);

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task LogOut_with_user_not_logged_in_should_be_unauthorized()
    {
        // Act
        Client.DefaultRequestHeaders.Authorization = null;
        var res = await Client.PostAsync("/logout", null);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task After_logout_it_should_not_allow_request_with_revoked_access_token()
    {
        // Arrange
        await Client.PostAsync("/logout", null);

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/verify-email", new VerifyEmail
        {
            Code = "SOME_RANDOM_CODE",
        });

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task LogOut_should_remove_refresh_token_cookie()
    {
        // Act
        var res = await Client.PostAsync("/logout", null);

        // Assert
        res.GetCookies()
            .Should()
            .Contain(x =>
                x.Name == AuthCookieNames.RefreshTokenCookieName && x.Expires < DateTimeHolder.MockedUtcNow &&
                x.Value == string.Empty);
    }
}