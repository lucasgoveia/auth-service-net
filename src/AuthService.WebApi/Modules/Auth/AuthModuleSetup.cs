using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Modules.Auth.UseCases;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.WebApi.Modules.Auth;

public static class AuthModuleSetup
{
    public static IServiceCollection AddAuthFunctionality(this IServiceCollection services)
    {
        services.AddScoped<LoginHandler>();
        services.AddScoped<RefreshTokenHandler>();
        services.AddScoped<LogOutHandler>();

        return services;
    }

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost("login",
                async ([FromBody] Login req, [FromServices] LoginHandler handler,
                    CancellationToken ct) => (await handler.Handle(req, ct)).ToApiResult())
            .AllowAnonymous();

        builder.MapPost("token",
                async ([FromServices] RefreshTokenHandler handler,
                    CancellationToken ct) => (await handler.Handle(ct)).ToApiResult())
            .AllowAnonymous();

        builder.MapPost("logout",
            async ([FromServices] LogOutHandler handler,
                CancellationToken ct) => (await handler.Handle(ct)).ToApiResult())
            .RequireAuthorization();;

        return builder;
    }
}