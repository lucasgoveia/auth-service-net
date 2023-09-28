namespace AuthService.WebApi.Messages.Events;

public record LoginAttemptSucceed
{
    public required long UserId { get; init; }
}