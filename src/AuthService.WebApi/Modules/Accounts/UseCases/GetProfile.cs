using System.Data;
using AuthService.Common.Consts;
using AuthService.WebApi.Common.Auth;
using Dapper;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record GetProfile
{
    public static readonly GetProfile Instance = new();
}

public record Profile
{
    public required SnowflakeId UserId { get; init; }
    public required string Name { get; init; }
    public string? AvatarLink { get; init; }
}

public class GetProfileHandler(IDbConnection dbConnection, ISessionManager sessionManager)
{
    public async Task<Result<Profile>> Handle(GetProfile request, CancellationToken ct)
    {
        var userId = sessionManager.UserId!.Value;

        var profile = await dbConnection.QuerySingleAsync<Profile>(
            $"SELECT id AS UserId, name, avatar_link FROM {TableNames.Users} WHERE id = @UserId",
            new { UserId = userId });

        return Result.Ok(profile);
    }
}