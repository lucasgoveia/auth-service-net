using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts;

public record UserEmail
{
    public SnowflakeId UserId { get; init; }
    public string Email { get; init; } = null!;
    public bool Verified { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }
}

public record User
{
    public SnowflakeId Id { get; init; }
    public string Name { get; init; } = null!;
    public string? AvatarLink { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }
    public bool LockoutEnabled { get; init; }
    public DateTime? LockoutEndDate { get; init; }
    public int AccessFailedCount { get; init; }
    public bool TwoFactorEnabled { get; init; }
    public List<UserEmail> UserEmails { get; init; } = [];

    public static User CreateNewUser(SnowflakeId id, string? name, string email, DateTime now)
    {
        return new User
        {
            Id = id,
            Name = name ?? email,
            CreatedAt = now,
            UpdatedAt = now,
            UserEmails =
            [
                new UserEmail
                {
                    UserId = id,
                    Email = email,
                    Verified = false,
                    CreatedAt = now,
                    UpdatedAt = now
                }
            ]
        };
    }
}