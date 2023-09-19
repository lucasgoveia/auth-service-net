namespace AuthService.WebApi.Modules.Accounts;

public record Identity
{
    public required long Id { get; init; }
    public long? UserId { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; init; }
    public string Email { get; init; } = null!;
    public bool EmailVerified { get; init; }
    public string PhoneNumber { get; init; } = null!;
    public bool PhoneNumberVerified { get; init; }
    public bool TwoFactorEnabled { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }
    public bool LockoutEnabled { get; init; }
    public DateTime? LockoutEndDate { get; init; }
    public int AccessFailedCount { get; init; }
    
    public static Identity CreateNewIdentity(long id, string username, string passwordHash, string email,
        DateTime now)
    {
        return new Identity
        {
            Id = id,
            Username = username.ToLower().Trim(),
            PasswordHash = passwordHash,
            Email = email.ToLower().Trim(),
            CreatedAt = now,
            UpdatedAt = now
        };
    }
}