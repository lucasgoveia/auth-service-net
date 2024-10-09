using AuthService.WebApi.Common.Auth;
using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Auth.UseCases;

public record ExchangePCKE
{
    public required string CodeVerifier { get; init; }
    public required string Code { get; init; }
    public required string RedirectUri { get; init; }
}

public record ExchangePCKEResponse
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
}

public class ExchangePCKEValidator : AbstractValidator<ExchangePCKE>
{
    public ExchangePCKEValidator()
    {
        RuleFor(x => x.CodeVerifier).NotEmpty();
        RuleFor(x => x.Code).NotEmpty();
        RuleFor(x => x.RedirectUri).NotEmpty();
    }
}

public class ExchangePCKEHandler(
    PCKEManager pckeManager,
    IAuthenticationService authenticationService
)
{
    public async Task<Result<ExchangePCKEResponse>> Handle(ExchangePCKE req, CancellationToken ct = default)
    {
        var result = await pckeManager.Exchange(req.Code, req.CodeVerifier, req.RedirectUri);

        if (!result.TryGetValue(out var pair))
        {
            return Result.Unauthorized();
        }

        var (accessToken, refreshToken) = await authenticationService.Authenticate(pair.userId, pair.credentialId, false, ct);

        return Result.Ok(new ExchangePCKEResponse { AccessToken = accessToken, RefreshToken = refreshToken });
    }
}