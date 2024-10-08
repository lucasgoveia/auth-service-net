using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases.Login;
using FluentAssertions;
using LucasGoveia.Results;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class UpdateProfileTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    public UpdateProfileTests(IntegrationTestFactory factory) : base(factory)
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

        res = await Client.PostAsJsonAsync("/login", new LoginWithEmailNPasswordData
        {
            Password = registerAccountRequest.Password,
            Email = registerAccountRequest.Email,
            RememberMe = true,
        });
        var accessToken = (await res.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken;

        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }

    [Fact]
    public async Task Update_profile_with_valid_data_should_be_success()
    {
        // Arrange
        var updateProfileRequest = new UpdateProfile
        {
            Name = "Test",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task Update_profile_with_valid_data_should_update_user_name()
    {
        // Arrange
        var updateProfileRequest = new UpdateProfile
        {
            Name = "Test",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        res.Should().BeSuccessful();

        var getProfileResponse = await Client.GetFromJsonAsync<Profile>("/accounts/profile");
        getProfileResponse!.Name.Should().Be(updateProfileRequest.Name);
    }

    [Fact]
    public async Task Update_profile_with_invalid_data_should_return_bad_request()
    {
        // Arrange
        var updateProfileRequest = new UpdateProfile
        {
            Name = "",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Update_profile_with_invalid_data_should_not_update_user_name()
    {
        // Arrange
        var updateProfileRequest = new UpdateProfile
        {
            Name = "",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var getProfileResponse = await Client.GetFromJsonAsync<Profile>("/accounts/profile");
        getProfileResponse!.Name.Should().NotBe(updateProfileRequest.Name);
    }

    [Fact]
    public async Task Update_profile_with_invalid_data_should_return_validation_errors()
    {
        // Arrange
        var updateProfileRequest = new UpdateProfile
        {
            Name = "",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        var resBody = await res.Content.ReadFromJsonAsync<AppError[]>();
        resBody.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Update_profile_with_unauthenticated_user_should_return_unauthorized()
    {
        // Arrange
        Client.DefaultRequestHeaders.Authorization = null;
        var updateProfileRequest = new UpdateProfile
        {
            Name = "Test",
        };

        // Act
        var res = await Client.PutAsJsonAsync("/accounts/profile", updateProfileRequest);

        // Assert
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}