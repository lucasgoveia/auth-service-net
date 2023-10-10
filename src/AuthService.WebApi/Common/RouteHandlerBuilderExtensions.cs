using AuthService.WebApi.Common.Auth.Requirements;

namespace AuthService.WebApi.Common;

public static class RouteHandlerBuilderExtensions
{
    public static TBuilder RequireNotAuthenticated<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder
            .RequireAuthorization(b => { b.AddRequirements(NotAuthenticated.Instance); });
    }
}