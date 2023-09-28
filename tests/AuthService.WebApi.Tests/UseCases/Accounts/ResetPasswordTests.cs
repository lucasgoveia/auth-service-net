using System.Net;
using System.Net.Http.Json;
using AngleSharp.Io;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Tests.Utils;
using FluentAssertions;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class ResetPasswordTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    private const string TestPassword = "Test1234!_345ax1";
    private string _code = null!;

    public ResetPasswordTests(IntegrationTestFactory factory) : base(factory)
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
        res.EnsureSuccessStatusCode();

        res = await Client.PostAsJsonAsync("/accounts/initiate-password-recovery", new InitiatePasswordRecovery
        {
            Email = "test@example.com"
        });
        res.EnsureSuccessStatusCode();

        var cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();
        Client.DefaultRequestHeaders.Add(HeaderNames.Cookie, cookies);
        _code = MessageBus.Messages.OfType<SendPasswordRecovery>().First().Code;
    }

    [Fact]
    public async Task ResetPassword_after_code_verification_should_return_ok()
    {
        // Arrange
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/reset-password", new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        });

        res.Should().BeSuccessful();
    }

    [Fact]
    public async Task ResetPassword_with_not_verified_code_should_return_forbidden()
    {
        // Act
        var res = await Client.PostAsJsonAsync("/accounts/reset-password", new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        });

        res.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ResetPassword_with_password_that_doesnt_comply_to_policy_should_return_bad_request()
    {
        // Arrange
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/reset-password", new ResetPassword
        {
            NewPassword = "WEAKPASSWORD"
        });

        res.Should().HaveStatusCode(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPassword_after_password_reset_should_terminate_limited_session()
    {
        // Arrange
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/reset-password", new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        });

        // Assert
        res.GetCookies()
            .Should()
            .Contain(x => x.Name == AuthCookieNames.SessionId && string.IsNullOrEmpty(x.Value) &&
                          x.Expires < DateTimeHolder.MockedUtcNow);
        res.GetCookies()
            .Should()
            .Contain(x => x.Name == AuthCookieNames.LimitedAccessToken && string.IsNullOrEmpty(x.Value) &&
                          x.Expires < DateTimeHolder.MockedUtcNow);
    }

    [Fact]
    public async Task ResetPassword_should_allow_login_with_new_password()
    {
        // Arrange
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var resetRequest = new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        };
        await Client.PostAsJsonAsync("/accounts/reset-password", resetRequest);
        
        // Assert
        var loginRes = await Client.PostAsJsonAsync("/login", new Login
        {
            Username = TestEmail,
            Password = resetRequest.NewPassword,
            RememberMe = false
        });
        loginRes.Should().BeSuccessful();
    }
    
    [Fact]
    public async Task ResetPassword_should_not_allow_login_with_old_password()
    {
        // Arrange
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var resetRequest = new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        };
        await Client.PostAsJsonAsync("/accounts/reset-password", resetRequest);
        
        // Assert
        var loginRes = await Client.PostAsJsonAsync("/login", new Login
        {
            Username = TestEmail,
            Password = TestPassword,
            RememberMe = false
        });
        loginRes.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ResetPassword_should_logout_all_sessions()
    {
        // Arrange
        var otherSessionsRefreshToken = new List<string[]>(capacity: 5);
        for (var i = 0; i < 5; ++i)
        {
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
        
        await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });

        // Act
        var resetRequest = new ResetPassword
        {
            NewPassword = "NewPassword123!_345ax1"
        };
        await Client.PostAsJsonAsync("/accounts/reset-password", resetRequest);
        
        // Assert
        foreach (var refreshCookie in otherSessionsRefreshToken)
        {
            // Other sessions refresh token should be revoked
            Client.DefaultRequestHeaders.Add("Cookie", refreshCookie);
            var res = await Client.PostAsync("/token", null!);
            res.Should().HaveStatusCode(HttpStatusCode.Unauthorized);
        }
    }
}