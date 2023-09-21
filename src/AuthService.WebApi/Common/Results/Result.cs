namespace AuthService.WebApi.Common.Results;

public record Result<T>
{
    private readonly SuccessResult<T>? _successResult;
    private readonly ErrorResult? _errorResult;
    public bool Success { get; }

    protected Result(SuccessResult<T> successResult)
    {
        _successResult = successResult;
        Success = true;
    }

    protected Result(ErrorResult errorResult)
    {
        _errorResult = errorResult;
        Success = false;
    }


    public static implicit operator Result<T>(SuccessResult<T> value)
    {
        return new(value);
    }


    public static implicit operator Result<T>(ErrorResult value)
    {
        return new(value);
    }

    public TE Match<TE>(Func<SuccessResult<T>, TE> successHandler, Func<ErrorResult, TE> errorHandler)
    {
        return Success
            ? successHandler(_successResult!)
            : errorHandler(_errorResult!);
    }

    public Result<T> Tap(Action<SuccessResult<T>> successHandler, Action<ErrorResult> errorHandler)
    {
        if (Success)
            successHandler(_successResult!);
        else
            errorHandler(_errorResult!);

        return this;
    }

    public Result<TE> Map<TE>(Func<T, TE> mapper)
    {
        return Success
            ? SuccessResult.Success<TE>(mapper(_successResult!))
            : _errorResult!;
    }

    public SuccessResult<T>? AsSuccess()
    {
        return _successResult;
    }

    public ErrorResult? AsError()
    {
        return _errorResult;
    }
}

public record Result : Result<Unit>
{
    protected Result(SuccessResult successResult) : base(successResult)
    {
    }

    protected Result(ErrorResult errorResult) : base(errorResult)
    {
    }

    public static implicit operator Result(ErrorResult value)
    {
        return new(value);
    }

    public static implicit operator Result(SuccessResult value)
    {
        return new(value);
    }
}