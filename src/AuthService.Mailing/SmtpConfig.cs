namespace AuthService.Mailing;

public record SmtpConfig
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required bool EnableSsl { get; init; }
    public required bool UseDefaultCredentials { get; init; }
    public required string UserName { get; init; }
    public required string Password { get; init; }
}