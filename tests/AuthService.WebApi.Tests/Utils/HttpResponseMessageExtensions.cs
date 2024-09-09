using System.Net;
using Microsoft.Net.Http.Headers;

namespace AuthService.WebApi.Tests.Utils;

public static class HttpResponseMessageExtensions
{
    public static List<Cookie> GetCookies(this HttpResponseMessage message)
    {
        message.Headers.TryGetValues(HeaderNames.SetCookie, out var cookiesHeader);

        var cookies = cookiesHeader?.Select(CreateCookie).ToList();
        return cookies ?? new List<Cookie>(capacity: 0);
    }

    public static Cookie CreateCookie(string cookieString)
    {
        var cookieProperties = cookieString.Split(';', StringSplitOptions.TrimEntries)
            .Select(x =>
            {
                var split = x.Split("=", StringSplitOptions.TrimEntries);
                return new KeyValuePair<string, string>(split[0], split.Length > 1 ? split[1] : "");
            })
            .ToList();


        var name = cookieProperties.First().Key;
        var value = cookieProperties.First(x => x.Key == name).Value;
        var path = cookieProperties.First(x => x.Key == "path").Value;
        var cookie = new Cookie(name, value, path)
        {
            Secure = cookieProperties.Any(x => x.Key == "secure"),
            HttpOnly = cookieProperties.Any(x => x.Key == "httponly"),
        };

        if (cookieProperties.Any(x => x.Key == "expires"))
        {
            var expires = cookieProperties.First(x => x.Key == "expires").Value;
            cookie.Expires = DateTime.Parse(expires).ToUniversalTime();
        }

        return cookie;
    }
}