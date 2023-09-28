using Microsoft.AspNetCore.Authorization;

namespace AuthService.WebApi.Common.Auth.Requirements;

public record RecoverCodeVerified : IAuthorizationRequirement
{
    public static readonly RecoverCodeVerified Instance = new();
}

public class RecoverCodeVerifiedHandler : AuthorizationHandler<RecoverCodeVerified>
{
    private readonly ISessionManager _sessionManager;

    public RecoverCodeVerifiedHandler(ISessionManager sessionManager)
    {
        _sessionManager = sessionManager;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        RecoverCodeVerified requirement)
    {
        if (await _sessionManager.GetSessionProperty<bool>(SessionPropertiesNames.VerifiedRecoveryCode))
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail();
        }
    }
}