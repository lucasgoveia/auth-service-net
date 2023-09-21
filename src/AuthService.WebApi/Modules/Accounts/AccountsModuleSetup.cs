using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Results;
using AuthService.WebApi.Common.Security;
using AuthService.WebApi.Modules.Accounts.Functionality;
using AuthService.WebApi.Modules.Accounts.UseCases;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.WebApi.Modules.Accounts;

public static class AccountsModuleSetup
{
    public static IServiceCollection AddAccountsFunctionality(this IServiceCollection services)
    {
        services.AddScoped<IUsernameAvailabilityChecker, UsernameAvailabilityChecker>();

        services.AddSingleton<IPasswordPolicy, PasswordPolicy>();

        services.AddScoped<RegisterAccountHandler>();
        services.AddScoped<InitiateEmailVerificationHandler>();
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<ChangePasswordHandler>();

        services.AddScoped<INewAccountSaver, NewAccountSaver>();

        services.AddScoped<IEmailVerificationCodeGenerator, EmailVerificationCodeGenerator>();
        services.AddScoped<IEmailVerificationCodeSender, EmailVerificationCodeSender>();
        services.AddScoped<IEmailVerificationCodeRepository, EmailVerificationCodeRepository>();
        services.AddScoped<IEmailVerificationManager, EmailVerificationManager>();
        services.AddScoped<IAccountEmailVerifiedSetter, AccountEmailVerifiedSetter>();

        services.AddScoped<IIdentityEmailGetter, IdentityEmailGetter>();

        services.AddScoped<IIdentityPasswordChanger, IdentityPasswordChanger>();

        return services;
    }

    public static IEndpointRouteBuilder MapAccountsEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost("accounts/register",
                async ([FromBody] RegisterAccount req, [FromServices] RegisterAccountHandler handler,
                        [FromServices] RequestPipe pipe, CancellationToken ct) =>
                    (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .AllowAnonymous();

        builder.MapPost("accounts/verify-email",
                async ([FromBody] VerifyEmail req, [FromServices] VerifyEmailHandler handler,
                        [FromServices] RequestPipe pipe, CancellationToken ct) =>
                    (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization();

        builder.MapPost("accounts/initiate-email-verification",
                async ([FromServices] InitiateEmailVerificationHandler handler, [FromServices] RequestPipe pipe,
                        CancellationToken ct) =>
                    (await pipe.Pipe(InitiateEmailVerification.Instance, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization();

        builder.MapPost("accounts/change-password", async ([FromServices] ChangePasswordHandler handler,
                    [FromServices] RequestPipe pipe, [FromBody] ChangePassword req, CancellationToken ct) =>
                (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization();

        return builder;
    }
}