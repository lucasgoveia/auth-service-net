using Microsoft.AspNetCore.Authorization;

namespace AuthService.WebApi.Common.Auth.Requirements;

public class NotAuthenticated : IAuthorizationRequirement
{
    public static NotAuthenticated Instance = new();
}

public class NotAuthenticatedHandler : AuthorizationHandler<NotAuthenticated>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        NotAuthenticated requirement)
    {
        if (!context.User.Identity!.IsAuthenticated)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}