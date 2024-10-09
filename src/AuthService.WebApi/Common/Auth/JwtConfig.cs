namespace AuthService.WebApi.Common.Auth;

public record JwtConfig
{
    public required string AccessTokenPrivateKey { get; init; }
    public required string AccessTokenPublicKey { get; init; }
    public required string RefreshTokenSecret { get; init; }
    public required int AccessTokenMinutesLifetime { get; init; }
    public required string Issuer { get; init; }
    public required int ResetPasswordTokenMinutesLifetime { get; init; }
    public required string ResetPasswordTokenSecret { get; init; }
}