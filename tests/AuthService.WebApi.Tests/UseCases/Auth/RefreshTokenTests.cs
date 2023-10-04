using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Utils;
using FluentAssertions;
using Microsoft.Net.Http.Headers;

namespace AuthService.WebApi.Tests.UseCases.Auth;

public class RefreshTokenTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private string[] _cookies = default!;
    private Cookie _refreshTokenCookie = default!;
    private string _accessToken = default!;

    public RefreshTokenTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    protected override async Task Seed()
    {
        await base.Seed();

        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
            Name = "Test User"
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
        _refreshTokenCookie = res.GetCookies().First(x => x.Name == AuthCookieNames.RefreshTokenCookieName);

    }

    [Fact]
    public async Task RefreshToken_with_valid_refresh_token_should_be_success()
    {
        // Act
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        var res = await Client.PostAsync("/token", null);

        // Assert
        res.Should().BeSuccessful();
    }


    [Fact]
    public async Task RefreshToken_without_providing_refresh_token_should_be_unauthorized()
    {
        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RefreshToken_refreshing_exactly_the_allowed_times_should_rotate_token()
    {
        // Arrange
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        for (var _ = 0; _ < (JwtConfig.RefreshTokenAllowedRenewsCount - 1); _++)
        {
            await Client.PostAsync("/token", null);
            DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(5);
        }

        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        var resCookie = res.GetCookies().First(x => x.Name == AuthCookieNames.RefreshTokenCookieName);
        resCookie.Value.Should().NotBe(_refreshTokenCookie.Value);
        resCookie.Value.Should().NotBeNullOrEmpty();
    }
    
    [Fact]
    public async Task RefreshToken_should_not_allow_after_token_rotation()
    {
        // Arrange
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        for (var _ = 0; _ < (JwtConfig.RefreshTokenAllowedRenewsCount - 1); _++)
        {
            await Client.PostAsync("/token", null);
            DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(5);
        }

        // Token rotation occurs here
        await Client.PostAsync("/token", null);
        
        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RefreshToken_after_token_expiration_should_be_unauthorized()
    {
        // Arrange
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        DateTimeHolder.MockedUtcNow =
            DateTimeHolder.MockedUtcNow.AddHours(JwtConfig.RefreshTokenInTrustedDevicesHoursLifetime + 1);

        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RefreshToken_in_non_trusted_device_should_not_extend_expiration()
    {
        // Arrange
        var registerAccountRequest = new Login
        {
            Username = "test@example.com",
            Password = "Test1234!_345ax1",
            RememberMe = false,
        };

        var loginRes = await Client.PostAsJsonAsync("/login", registerAccountRequest);
        var cookies = loginRes.Headers.GetValues(HeaderNames.SetCookie).ToArray();

        Client.DefaultRequestHeaders.Add("Cookie", cookies);

        for (var _ = 0; _ < JwtConfig.RefreshTokenAllowedRenewsCount - 1; _++)
        {
            var resMsg = await Client.PostAsync("/token", null);
            resMsg.EnsureSuccessStatusCode();
            DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(5);
        }

        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        var rotatedRefreshCookie = res.GetCookies().First(x => x.Name == AuthCookieNames.RefreshTokenCookieName);
        var ttl = rotatedRefreshCookie.Expires - DateTimeHolder.MockedUtcNow;
        ttl.Should().NotBe(TimeSpan.FromHours(JwtConfig.RefreshTokenHoursLifetime));
        ttl.Should().BeLessThan(TimeSpan.FromHours(JwtConfig.RefreshTokenHoursLifetime));
    }

    [Fact]
    public async Task RefreshToken_in_trusted_device_should_extend_expiration()
    {
        // Arrange
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
        Client.DefaultRequestHeaders.Add("Cookie", _cookies);
        await Client.PostAsync("/logout", null);
        var registerAccountRequest = new Login
        {
            Username = "test@example.com",
            Password = "Test1234!_345ax1",
            RememberMe = true,
        };

        var loginRes = await Client.PostAsJsonAsync("/login", registerAccountRequest);
        var cookies = loginRes.Headers.GetValues(HeaderNames.SetCookie).ToArray();

        Client.DefaultRequestHeaders.Add("Cookie", cookies);

        for (var _ = 0; _ < JwtConfig.RefreshTokenAllowedRenewsCount - 1; _++)
        {
            await Client.PostAsync("/token", null);
            DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddMinutes(5);
        }

        // Act
        var res = await Client.PostAsync("/token", null);

        // Assert
        var rotatedRefreshCookie = res.GetCookies().First(x => x.Name == AuthCookieNames.RefreshTokenCookieName);
        var cookieLifetime = rotatedRefreshCookie.Expires - DateTimeHolder.MockedUtcNow;
        cookieLifetime.Should().Be(TimeSpan.FromHours(JwtConfig.RefreshTokenInTrustedDevicesHoursLifetime));
    }
}