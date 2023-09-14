using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthService.WebApi.Common.Auth;

public interface ISession
{
    long? AccountId { get; }
    bool IsAuthenticated { get; }
}

public class Session : ISession
{
    public long? AccountId { get; init; }
    public bool IsAuthenticated => AccountId.HasValue;

    public Session(IHttpContextAccessor httpContextAccessor)
    {
        var user = httpContextAccessor.HttpContext?.User;

        var accountId = user?.FindFirstValue(ClaimTypes.NameIdentifier);

        if (accountId is null)
        {
            return;
        }

        AccountId = long.Parse(accountId);
    }
}