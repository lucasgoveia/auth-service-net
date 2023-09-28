using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class GetProfileTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    public GetProfileTests(IntegrationTestFactory factory) : base(factory)
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
        
        var accessToken = (await res.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken;

        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        
        var updateProfileRequest = new UpdateProfile
        {
            Name = "Test",
        };
        
        await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);
    }
    
    [Fact]
    public async Task Get_profile_should_return_success()
    {
        // Act
        var res = await Client.GetAsync("/accounts/profile");

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Get_profile_should_return_user_profile()
    {
        // Act
        var res = await Client.GetAsync("/accounts/profile");

        // Assert
        var profile = await res.Content.ReadFromJsonAsync<Profile>();
        profile.Should().BeEquivalentTo(new
        {
            Name = "Test",
            AvatarLink = (string?)null
        });
    }
    
    [Fact]
    public async Task Get_profile_with_unauthorized_user_should_return_unauthorized()
    {
        // Arrange
        Client.DefaultRequestHeaders.Authorization = null;

        // Act
        var res = await Client.GetAsync("/accounts/profile");

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}