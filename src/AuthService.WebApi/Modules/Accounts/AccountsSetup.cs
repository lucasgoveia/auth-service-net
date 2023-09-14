using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Modules.Accounts.Functionality;
using AuthService.WebApi.Modules.Accounts.UseCases;
using Microsoft.AspNetCore.Mvc;
using ISession = AuthService.WebApi.Common.Auth.ISession;

namespace AuthService.WebApi.Modules.Accounts;

public static class AccountsSetup
{
    public static IServiceCollection AddAccountsFunctionality(this IServiceCollection services)
    {
        services.AddScoped<IUsernameAvailabilityChecker, UsernameAvailabilityChecker>();
        services.AddSingleton<IPasswordPolicy, PasswordPolicy>();
        services.AddScoped<RegisterAccountHandler>();
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<INewAccountSaver, NewAccountSaver>();

        services.AddTransient<IEmailVerificationCodeGenerator, EmailVerificationCodeGenerator>();
        services.AddTransient<IEmailVerificationCodeSender, EmailVerificationCodeSender>();
        services.AddTransient<IEmailVerificationCodeRepository, EmailVerificationCodeRepository>();
        services.AddTransient<IEmailVerificationManager, EmailVerificationManager>();

        services.AddTransient<IAccountEmailVerifiedSetter, AccountEmailVerifiedSetter>();
        

        return services;
    }

    public static IEndpointRouteBuilder MapAccountsEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost("accounts/register",
            async ([FromBody] RegisterAccount req, [FromServices] RegisterAccountHandler handler,
                CancellationToken ct) => (await handler.Handle(req, ct)).ToApiResult())
            .AllowAnonymous();

        builder.MapPost("accounts/email-verification",
            async ([FromBody] VerifyEmail req, [FromServices] VerifyEmailHandler handler,
                CancellationToken ct) => (await handler.Handle(req, ct)).ToApiResult())
            .RequireAuthorization();

        return builder;
    }
}