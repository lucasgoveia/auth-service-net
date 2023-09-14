namespace AuthService.WebApi.Common.Timestamp;

public delegate DateTime UtcNow();

public static class TimestampUtils
{
    public static DateTime UtcNow()
    {
        return DateTime.Now;
    }
}