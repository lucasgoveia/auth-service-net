using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts;

public record Identity
{
    public required SnowflakeId Id { get; init; }
    public SnowflakeId? UserId { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }

    public static Identity CreateNewIdentity(SnowflakeId userId, SnowflakeId id, string username, string passwordHash, DateTime now)
    {
        return new Identity
        {
            Id = id,
            UserId = userId,
            Username = username.ToLower().Trim(),
            PasswordHash = passwordHash,
            CreatedAt = now,
            UpdatedAt = now
        };
    }
}