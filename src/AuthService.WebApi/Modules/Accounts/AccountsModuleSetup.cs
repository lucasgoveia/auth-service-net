using AuthService.Common.Security;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Auth.Requirements;
using AuthService.WebApi.Common.ResultExtensions;
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
        services.AddScoped<UpdateProfileHandler>();
        services.AddScoped<GetProfileHandler>();
        services.AddScoped<InitiatePasswordRecoveryHandler>();
        services.AddScoped<VerifyPasswordRecoveryCodeHandler>();
        services.AddScoped<ResetPasswordHandler>();

        services.AddScoped<INewAccountSaver, NewAccountSaver>();

        services.AddScoped<IEmailVerificationCodeRepository, EmailVerificationCodeRepository>();
        services.AddScoped<IEmailVerificationManager, EmailVerificationManager>();
        services.AddScoped<IAccountEmailVerifiedSetter, AccountEmailVerifiedSetter>();

        services.AddScoped<IPasswordRecoveryCodeRepository, PasswordRecoveryCodeRepository>();
        services.AddScoped<IPasswordRecoveryManager, PasswordRecoveryManager>();

        services.AddScoped<IUserEmailGetter, UserEmailGetter>();

        services.AddScoped<IIdentityPasswordChanger, IdentityPasswordChanger>();

        services.AddScoped<IProfileUpdater, ProfileUpdater>();

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
            .RequireAuthorization(b =>
            {
                b.AuthenticationSchemes = new[] { CustomJwtAuthentication.Scheme, LimitedSessionAuthentication.Scheme };
                b.RequireAuthenticatedUser();
            });

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

        builder.MapPut("accounts/profile", async ([FromServices] UpdateProfileHandler handler,
                    [FromServices] RequestPipe pipe, [FromBody] UpdateProfile req, CancellationToken ct) =>
                (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization();

        builder.MapGet("accounts/profile", async ([FromServices] GetProfileHandler handler, CancellationToken ct) =>
                (await handler.Handle(GetProfile.Instance, ct)).ToApiResult()
            )
            .RequireAuthorization();

        builder.MapPost("accounts/initiate-password-recovery", async (
                    [FromServices] InitiatePasswordRecoveryHandler handler,
                    [FromServices] RequestPipe pipe, [FromBody] InitiatePasswordRecovery req, CancellationToken ct) =>
                (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .AllowAnonymous();

        builder.MapPost("accounts/verify-password-recovery-code", async (
                    [FromServices] VerifyPasswordRecoveryCodeHandler handler,
                    [FromServices] RequestPipe pipe, [FromBody] VerifyPasswordRecoveryCode req, CancellationToken ct) =>
                (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization(b =>
            {
                b.AuthenticationSchemes = new[] { LimitedSessionAuthentication.Scheme };
                b.RequireAuthenticatedUser();
            });

        builder.MapPost("accounts/reset-password", async (
                    [FromServices] ResetPasswordHandler handler,
                    [FromServices] RequestPipe pipe, [FromBody] ResetPassword req, CancellationToken ct) =>
                (await pipe.Pipe(req, handler.Handle, ct)).ToApiResult()
            )
            .RequireAuthorization(b =>
            {
                b.AuthenticationSchemes = new[] { LimitedSessionAuthentication.Scheme };
                b.AddRequirements(RecoverCodeVerified.Instance);
                b.RequireAuthenticatedUser();
            });

        return builder;
    }
}