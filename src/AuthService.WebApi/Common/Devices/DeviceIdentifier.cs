namespace AuthService.WebApi.Common.Devices;

public record DeviceDto
{
    public required string Fingerprint { get; init; }
    public required string UserAgent { get; init; }
    public required string IpAddress { get; init; }
}

public class DeviceIdentifier(IHttpContextAccessor httpContextAccessor) : IDeviceIdentifier
{
    public DeviceDto Identify()
    {
        var userAgent = httpContextAccessor.HttpContext!.Request.Headers["User-Agent"].ToString();
        var fingerprint = httpContextAccessor.HttpContext!.Request.Headers["Fingerprint"].ToString();
        var ipAddress = httpContextAccessor.HttpContext!.Connection.RemoteIpAddress!.ToString();

        return new DeviceDto
        {
            Fingerprint = fingerprint,
            IpAddress = ipAddress,
            UserAgent = userAgent.Length > 200 ? userAgent[..200] : userAgent
        };
    }
}

public interface IDeviceIdentifier
{
    DeviceDto Identify();
}