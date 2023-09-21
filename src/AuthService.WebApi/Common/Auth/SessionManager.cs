using System.Security.Claims;

namespace AuthService.WebApi.Common.Auth;

public interface ISessionManager
{
    long? IdentityId { get; }
    bool IsAuthenticated { get; }
}

public class SessionManagerManager : ISessionManager
{
    public long? IdentityId { get; init; }
    public bool IsAuthenticated => IdentityId.HasValue;

    public SessionManagerManager(IHttpContextAccessor httpContextAccessor)
    {
        var user = httpContextAccessor.HttpContext?.User;

        var accountId = user?.FindFirstValue(ClaimTypes.NameIdentifier);

        if (accountId is null)
        {
            return;
        }

        IdentityId = long.Parse(accountId);
    }
}