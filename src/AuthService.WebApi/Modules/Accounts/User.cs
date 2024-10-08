﻿using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts;

public record User
{
    public SnowflakeId Id { get; init; }
    public string Name { get; init; } = null!;
    public string? AvatarLink { get; init; }
    public string? Email { get; init; }
    public bool EmailVerified { get; init; }
    public string? PhoneNumber { get; init; }
    public bool PhoneNumberVerified { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
    public DateTime? DeletedAt { get; init; }
    public bool LockoutEnabled { get; init; }
    public DateTime? LockoutEndDate { get; init; }
    public int AccessFailedCount { get; init; }
    public bool TwoFactorEnabled { get; init; }
    
    public static User CreateNewUser(SnowflakeId id, string email, string? name, DateTime now)
    {
        return new User
        {
            Id = id,
            Name = name ?? email,
            Email = email,
            CreatedAt = now,
            UpdatedAt = now
        };
    }
}