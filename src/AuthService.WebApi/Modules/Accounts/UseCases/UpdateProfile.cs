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

public class UpdateProfileHandler(ISessionManager sessionManager, UtcNow utcNow, IProfileUpdater profileUpdater)
{
    public async Task<Result> Handle(UpdateProfile request, CancellationToken ct)
    {
        var userId = sessionManager.UserId!.Value;
        await profileUpdater.UpdateProfile(userId, request.Name, utcNow(), ct);

        return SuccessResult.Success();
    }
}

public interface IProfileUpdater
{
    Task UpdateProfile(long userId, string name, DateTime utcNow, CancellationToken ct);
}

public class ProfileUpdater(IDbConnection dbConnection) : IProfileUpdater
{
    public async Task UpdateProfile(long userId, string name, DateTime utcNow, CancellationToken ct)
    {
        await dbConnection.ExecuteAsync(
            $"UPDATE {TableNames.Users} SET name = @name, updated_at = @utcNow WHERE id = @userId",
            new { name, utcNow, userId });
    }
}