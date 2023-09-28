namespace AuthService.WebApi.Messages.Events;

public record LoginAttemptFailed
{
    public required long UserId { get; init; }
}