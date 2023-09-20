using System.Security.Claims;

namespace AuthService.WebApi.Common;

public interface ISession
{
    long? IdentityId { get; }
    bool IsAuthenticated { get; }
}

public class Session : ISession
{
    public long? IdentityId { get; init; }
    public bool IsAuthenticated => IdentityId.HasValue;

    public Session(IHttpContextAccessor httpContextAccessor)
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