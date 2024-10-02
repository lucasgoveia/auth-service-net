using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Messages.Events;

public record LoginAttemptFailed
{
    public required SnowflakeId UserId { get; init; }
}