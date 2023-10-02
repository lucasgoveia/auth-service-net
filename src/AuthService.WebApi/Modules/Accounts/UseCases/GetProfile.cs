using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.WebApi.Common.Auth;
using Dapper;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record GetProfile
{
    public static GetProfile Instance = new();
}

public record Profile
{
    public required long UserId { get; init; }
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

        return SuccessResult.Success(profile);
    }
}