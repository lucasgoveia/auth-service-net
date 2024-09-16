using System.Diagnostics;

namespace AuthService.WebApi;

public static class ApiActivitySource
{
    public const string ServiceName = "AuthService.WebApi";
    public static readonly ActivitySource Instance = new(ServiceName);
}