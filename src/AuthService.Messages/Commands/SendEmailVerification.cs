namespace AuthService.WebApi.Messages.Commands;

public record SendEmailVerification
{
    public required string Email { get; init; }
    public required string Code { get; init; }
}