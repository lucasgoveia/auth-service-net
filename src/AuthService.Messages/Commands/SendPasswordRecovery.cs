namespace AuthService.WebApi.Messages.Commands;

public record SendPasswordRecovery
{
    public required string Email { get; init; }
    public required string Code { get; init; }
    public required int CodeExpirationMinutes { get; init; }
}