using System.Net;
using AngleSharp.Io;

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
        var properties = cookieString.Split(';', StringSplitOptions.TrimEntries);
        var name = properties[0].Split("=")[0];
        var value = properties[0].Split("=")[1];
        var path = properties[2].Replace("path=", "");
        var cookie = new Cookie(name, value, path)
        {
            Secure = properties.Contains("secure"),
            HttpOnly = properties.Contains("httponly"),
            Expires = DateTime.Parse(properties[1].Replace("expires=", "")).ToUniversalTime(),
        };
        return cookie;
    }
}