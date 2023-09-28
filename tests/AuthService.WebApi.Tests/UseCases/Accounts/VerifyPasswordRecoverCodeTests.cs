using System.Net;
using System.Net.Http.Json;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using FluentAssertions;
using Microsoft.Net.Http.Headers;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class VerifyPasswordRecoverCodeTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    private const string TestEmail = "test@example.com";
    private const string TestPassword = "Test1234!_345ax1";
    private string[] _cookies = null!;
    private string _code = null!;
    
    public VerifyPasswordRecoverCodeTests(IntegrationTestFactory factory) : base(factory)
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
        
        _cookies = res.Headers.GetValues(HeaderNames.SetCookie).ToArray();
        Client.DefaultRequestHeaders.Add(HeaderNames.Cookie, _cookies); 
        _code = MessageBus.Messages.OfType<SendPasswordRecovery>().First().Code;
    }
    
    [Fact]
    public async Task VerifyPasswordRecoverCode_with_valid_code_should_return_ok()
    {
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
    
    [Fact]
    public async Task VerifyPasswordRecoverCode_with_invalid_code_should_return_bad_request()
    {
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = "invalid-code"
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
    
    [Fact]
    public async Task VerifyPasswordRecoverCode_with_nonexistent_code_should_return_bad_request()
    {
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = "123456"
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
    
    [Fact]
    public async Task VerifyPasswordRecoverCode_with_expired_session_should_return_unauthorized()
    {
        DateTimeHolder.MockedUtcNow = DateTimeHolder.MockedUtcNow.AddHours(1);
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
    
    [Fact]
    public async Task VerifyPasswordRecoverCode_with_utilized_code_should_return_bad_request() 
    {
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
    
    [Fact]
    public async Task VerifiyPasswordRecoverCode_with_unauthroized_user_should_return_unauthorized()
    {
        Client.DefaultRequestHeaders.Remove(HeaderNames.Cookie);
        var response = await Client.PostAsJsonAsync("/accounts/verify-password-recovery-code", new VerifyPasswordRecoveryCode
        {
            Code = _code
        });
        
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

}