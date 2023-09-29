namespace AuthService.Mailing;

public record MailConfig
{
    public required string FromEmail { get; init; }
    public required string FromName { get; init; }
}