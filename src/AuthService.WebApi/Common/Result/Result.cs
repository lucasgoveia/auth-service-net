namespace AuthService.WebApi.Common.Result;

public record Result<T>
{
    private readonly SuccessResult<T>? _successResult;
    private readonly ErrorResult? _errorResult;
    private readonly bool _success;

    protected Result(SuccessResult<T> successResult)
    {
        _successResult = successResult;
        _success = true;
    }

    protected Result(ErrorResult errorResult)
    {
        _errorResult = errorResult;
        _success = false;
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
        return _success
            ? successHandler(_successResult!)
            : errorHandler(_errorResult!);
    }
    
    public Result<TE> Map<TE>(Func<T, TE> mapper)
    {
        return _success
            ? SuccessResult.Success<TE>(mapper(_successResult!))
            : _errorResult!;
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