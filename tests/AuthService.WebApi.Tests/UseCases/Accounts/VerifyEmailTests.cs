using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Tests.Fakes;
using Dapper;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class VerifyEmailTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private string _code = null!;
    private const string TestEmail = "test@example.com";

    public VerifyEmailTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    protected override async Task Seed()
    {
        await base.Seed();
        var registerAccountRequest = new RegisterAccount
        {
            Email = TestEmail,
            Password = "Test1234!_345ax1",
        };

        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        var accessToken = (await res.Content.ReadFromJsonAsync<RegisterAccountResponse>())!.AccessToken;

        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var sendEmailVerification = ((FakeMessageBus)MessageBus)!.Messages.Cast<SendEmailVerification>().First();
        _code = sendEmailVerification.Code;
    }

    [Fact]
    public async Task Verify_email_with_valid_code_returns_success()
    {
        // Arrange
        var verifyEmailRequest = new VerifyEmail
        {
            Code = _code,
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/verify-email", verifyEmailRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Verifiy_email_should_set_identity_email_as_verified()
    {
        // Arrange
        var verifyEmailRequest = new VerifyEmail
        {
            Code = _code,
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/verify-email", verifyEmailRequest);

        // Assert
        (await Factory.Services.GetRequiredService<IDbConnection>().ExecuteScalarAsync<bool>(
                $"SELECT email_verified FROM {TableNames.Identities} WHERE email = @Email", new { Email = TestEmail }))
            .Should()
            .BeTrue();
    }

    [Fact]
    public async Task Verify_email_with_invalid_code_returns_error()
    {
        // Arrange
        var verifyEmailRequest = new VerifyEmail
        {
            Code = "invalid-code",
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/verify-email", verifyEmailRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Verify_email_with_not_authenticated_user_returns_unauthorized()
    {
        // Arrange
        Client.DefaultRequestHeaders.Authorization = null;
        var verifyEmailRequest = new VerifyEmail
        {
            Code = _code,
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/verify-email", verifyEmailRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}