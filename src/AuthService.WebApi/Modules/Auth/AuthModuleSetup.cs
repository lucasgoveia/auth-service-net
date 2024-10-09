using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Modules.Auth.UseCases;
using AuthService.WebApi.Modules.Auth.UseCases.Login;
using LucasGoveia.Results.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.WebApi.Modules.Auth;

public static class AuthModuleSetup
{
    public static IServiceCollection AddAuthFunctionality(this IServiceCollection services)
    {
        services.AddScoped<LoginWithEmailNPasswordHandler>();
        services.AddScoped<RefreshTokenHandler>();
        services.AddScoped<LogOutHandler>();
        services.AddScoped<ExchangePCKEHandler>();
        services.AddScoped<PCKEManager>();

        return services;
    }

    private static async Task<IResult> LoginWithEmailNPassword(
        [FromServices] LoginWithEmailNPasswordHandler handler,
        [FromServices] RequestPipe pipe,
        [FromBody] LoginWithEmailNPasswordData body,
        [FromQuery] string codeChallenge,
        [FromQuery] string codeChallengeMethod,
        [FromQuery] string redirectUri,
        CancellationToken ct
    )
    {
        var req = new LoginWithEmailNPassword
        {
            Body = body,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RedirectUri = redirectUri
        };

        return (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult();
    }
    
    private static async Task<IResult> ExchangePCKE(
        [FromServices] ExchangePCKEHandler handler,
        [FromServices] RequestPipe pipe,
        [FromBody] ExchangePCKE body,
        CancellationToken ct
    ) => (await pipe.Pipe(body, handler.Handle, ct)).ToApiResult();


    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost("login", LoginWithEmailNPassword)
            .RequireNotAuthenticated();

        builder.MapPost("exchange-pcke", ExchangePCKE);

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