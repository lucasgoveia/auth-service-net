namespace AuthService.WebApi.Common.Devices;

public record DeviceDto
{
    public required string Fingerprint { get; init; }
    public required string UserAgent { get; init; }
    public required string IpAddress { get; init; }
}

public class DeviceIdentifier : IDeviceIdentifier
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DeviceIdentifier(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public DeviceDto Identify()
    {
        var userAgent = _httpContextAccessor.HttpContext!.Request.Headers["User-Agent"].ToString();
        var fingerprint = _httpContextAccessor.HttpContext!.Request.Headers["Device-Fingerprint"].ToString();
        var ipAddress = _httpContextAccessor.HttpContext!.Connection.RemoteIpAddress!.ToString();

        return new DeviceDto
        {
            Fingerprint = fingerprint,
            IpAddress = ipAddress,
            UserAgent = userAgent
        };
    }
}

public interface IDeviceIdentifier
{
    DeviceDto Identify();
}