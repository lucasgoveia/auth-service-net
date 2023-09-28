namespace AuthService.Common.Timestamp;

public delegate DateTime UtcNow();

public static class TimestampUtils
{
    public static DateTime UtcNow()
    {
        return DateTime.UtcNow;
    }
}