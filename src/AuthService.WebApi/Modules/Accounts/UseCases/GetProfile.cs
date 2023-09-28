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

public class GetProfileHandler
{
    private readonly IDbConnection _dbConnection;
    private readonly ISessionManager _sessionManager;

    public GetProfileHandler(IDbConnection dbConnection, ISessionManager sessionManager)
    {
        _dbConnection = dbConnection;
        _sessionManager = sessionManager;
    }

    public async Task<Result<Profile>> Handle(GetProfile request, CancellationToken ct)
    {
        var userId = _sessionManager.UserId!.Value;

        var profile = await _dbConnection.QuerySingleAsync<Profile>(
            $"SELECT id AS UserId, name, avatar_link FROM {TableNames.Users} WHERE id = @UserId",
            new { UserId = userId });

        return SuccessResult.Success(profile);
    }
}