﻿using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Auth.UseCases;
using LucasGoveia.Results.AspNetCore;
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
                async ([FromBody] Login req, [FromServices] LoginHandler handler, [FromServices] RequestPipe pipe,
                    CancellationToken ct) => (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireNotAuthenticated();

        builder.MapPost("token",
                async ([FromServices] RefreshTokenHandler handler, [FromServices] RequestPipe pipe,
                        CancellationToken ct) =>
                    (await pipe.Pipe(RefreshToken.Instance, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization(b =>
            {
                b.AuthenticationSchemes = new[] { RefreshTokenAuthentication.Scheme };
                b.RequireAuthenticatedUser();
            });

        builder.MapPost("logout",
                async ([FromServices] LogOutHandler handler, [FromServices] RequestPipe pipe,
                    CancellationToken ct) => (await pipe.Pipe(LogOut.Instance, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization();

        return builder;
    }
}