using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts;

public enum CredentialType
{
    Email,
    Username,
    Phone,
    Social,
    B2B,
    PassKey
}

public static class CredentialTypeExtensions
{
    public static string ToDbValue(this CredentialType type)
    {
        return type switch
        {
            CredentialType.Email => "email",
            CredentialType.Username => "username",
            CredentialType.Phone => "phone",
            CredentialType.Social => "social",
            CredentialType.B2B => "b2b",
            CredentialType.PassKey => "passkey",
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }
}

public record CredentialData
{
    public required SnowflakeId Id { get; init; }
    public SnowflakeId UserId { get; init; }
    public required CredentialType Type { get; init; }
    public required string Identifier { get; init; }
    public string? Secret { get; init; }
    public string? Provider { get; init; }
    public bool Verified { get; init; }
    public required DateTime CreatedAt { get; init; }
    public required DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }
}

public interface ICredential
{
    public CredentialData ToCredentialData();
}

public record EmailPasswordCredential : ICredential
{
    public required SnowflakeId Id { get; init; }
    public SnowflakeId UserId { get; init; }
    public required string Email { get; init; }
    public required string PasswordHash { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }

    public CredentialData ToCredentialData()
    {
        return new CredentialData
        {
            Id = Id,
            UserId = UserId,
            Type = CredentialType.Email,
            Identifier = Email,
            Secret = PasswordHash,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
            DeletedAt = DeletedAt
        };
    }

    public static EmailPasswordCredential Create(SnowflakeId userId, SnowflakeId id, string email, string passwordHash,
        DateTime now)
    {
        return new EmailPasswordCredential
        {
            Id = id,
            UserId = userId,
            Email = email.ToLower().Trim(),
            PasswordHash = passwordHash,
            CreatedAt = now,
            UpdatedAt = now
        };
    }
}

public record SocialCredential : ICredential
{
    public required SnowflakeId Id { get; init; }
    public SnowflakeId UserId { get; init; }
    public required string Provider { get; init; }
    public required string ProviderId { get; init; }
    public required string Email { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }

    public CredentialData ToCredentialData()
    {
        return new CredentialData
        {
            Id = Id,
            UserId = UserId,
            Type = CredentialType.Social,
            Identifier = ProviderId,
            Secret = Provider,
            Provider = Provider,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
            DeletedAt = DeletedAt
        };
    }

    public static SocialCredential Create(SnowflakeId userId, SnowflakeId id, string provider, string providerId,
        string email, DateTime now)
    {
        return new SocialCredential
        {
            Id = id,
            UserId = userId,
            Provider = provider,
            ProviderId = providerId,
            Email = email.ToLower().Trim(),
            CreatedAt = now,
            UpdatedAt = now
        };
    }
}