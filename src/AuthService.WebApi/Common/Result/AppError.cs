namespace AuthService.WebApi.Common.Result;

public record AppError
{
    public required string ErrorMessage { get; init; }
    public required string ErrorCode { get; init; }
}