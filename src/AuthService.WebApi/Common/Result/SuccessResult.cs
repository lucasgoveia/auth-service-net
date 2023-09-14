namespace AuthService.WebApi.Common.Result;

public record SuccessResult<T>
{
    public required T Value { get; init; }

    public static implicit operator T(SuccessResult<T> result) => result.Value;
    public static implicit operator SuccessResult<T>(T value) => new() { Value = value };
}

public record SuccessResult : SuccessResult<Unit>
{
    public static SuccessResult Success()
    {
        return new SuccessResult { Value = Unit.Value};
    }
    
    public static SuccessResult<T> Success<T>(T value)
    {
        return new SuccessResult<T> { Value = value };
    }
}