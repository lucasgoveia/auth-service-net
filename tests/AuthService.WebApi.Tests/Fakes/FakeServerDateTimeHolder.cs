namespace AuthService.WebApi.Tests.Fakes;

public class FakeServerDateTimeHolder
{
    public static DateTime DefaultUtcNow = new(2021, 1, 1, 1, 1, 1, DateTimeKind.Utc);
    public DateTime MockedUtcNow { get; set; } = DefaultUtcNow;
}