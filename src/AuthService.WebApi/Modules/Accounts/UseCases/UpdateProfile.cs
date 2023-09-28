using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Results;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Auth;
using Dapper;
using FluentValidation;

namespace AuthService.WebApi.Modules.Accounts.UseCases;

public record UpdateProfile
{
    public required string Name { get; init; }
}

public class UpdateProfileValidator : AbstractValidator<UpdateProfile>
{
    public UpdateProfileValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
    }
}

public class UpdateProfileHandler
{
    private readonly ISessionManager _sessionManager;
    private readonly UtcNow _utcNow;
    private readonly IProfileUpdater _profileUpdater;

    public UpdateProfileHandler(ISessionManager sessionManager, UtcNow utcNow, IProfileUpdater profileUpdater)
    {
        _sessionManager = sessionManager;
        _utcNow = utcNow;
        _profileUpdater = profileUpdater;
    }

    public async Task<Result> Handle(UpdateProfile request, CancellationToken ct)
    {
        var userId = _sessionManager.UserId!.Value;
        await _profileUpdater.UpdateProfile(userId, request.Name, _utcNow(), ct);

        return SuccessResult.Success();
    }
}

public interface IProfileUpdater
{
    Task UpdateProfile(long userId, string name, DateTime utcNow, CancellationToken ct);
}

public class ProfileUpdater : IProfileUpdater
{
    private readonly IDbConnection _dbConnection;

    public ProfileUpdater(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task UpdateProfile(long userId, string name, DateTime utcNow, CancellationToken ct)
    {
        await _dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET name = @name, updated_at = @utcNow WHERE id = @userId",
            new { name, utcNow, userId });
    }
}