using System.Net;
using System.Net.Http.Json;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Accounts.UseCases;
using FluentAssertions;
using Microsoft.Net.Http.Headers;

namespace AuthService.WebApi.Tests.UseCases.Auth;

public class RefreshTokenTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private string[] _cookies = default!;

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
        };

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
        _cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();
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
    public async Task RefreshToken_with_invalid_refresh_token_should_be_unauthorized()
    {
        // Act
        Client.DefaultRequestHeaders.Add("Cookie", new[] { $"{AuthenticationService.RefreshTokenCookieName}=invalid" });
        var res = await Client.PostAsync("/token", null);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}