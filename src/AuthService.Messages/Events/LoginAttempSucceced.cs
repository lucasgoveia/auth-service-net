using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Messages.Events;

public record LoginAttemptSucceed
{
    public required SnowflakeId UserId { get; init; }
}