using AuthService.WebApi.Common.Result;
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
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<InitiateEmailVerificationHandler>();
        
        services.AddScoped<INewAccountSaver, NewAccountSaver>();
        
        services.AddTransient<IEmailVerificationCodeGenerator, EmailVerificationCodeGenerator>();
        services.AddTransient<IEmailVerificationCodeSender, EmailVerificationCodeSender>();
        services.AddTransient<IEmailVerificationCodeRepository, EmailVerificationCodeRepository>();
        services.AddTransient<IEmailVerificationManager, EmailVerificationManager>();
        services.AddTransient<IAccountEmailVerifiedSetter, AccountEmailVerifiedSetter>();

        services.AddTransient<IIdentityEmailGetter, IdentityEmailGetter>();

        return services;
    }

    public static IEndpointRouteBuilder MapAccountsEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost("accounts/register",
                async ([FromBody] RegisterAccount req, [FromServices] RegisterAccountHandler handler,
                    CancellationToken ct) => (await handler.Handle(req, ct)).ToApiResult())
            .AllowAnonymous();

        builder.MapPost("accounts/verify-email",
                async ([FromBody] VerifyEmail req, [FromServices] VerifyEmailHandler handler,
                    CancellationToken ct) => (await handler.Handle(req, ct)).ToApiResult())
            .RequireAuthorization();
        
        builder.MapPost("accounts/initiate-email-verification",
                async ([FromServices] InitiateEmailVerificationHandler handler,
                    CancellationToken ct) => (await handler.Handle(ct)).ToApiResult())
            .RequireAuthorization();

        return builder;
    }
}