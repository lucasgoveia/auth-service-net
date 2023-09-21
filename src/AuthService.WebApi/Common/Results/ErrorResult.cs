namespace AuthService.WebApi.Common.Results;

public record ErrorResult
{
    public required ErrorType ErrorType { get; init; }
    public required IList<AppError> Errors { get; init; }

    public static ErrorResult Error(params AppError[] appErrors)
    {
        return new ErrorResult { Errors = appErrors.ToList(), ErrorType = ErrorType.Error };
    }

    public static ErrorResult Invalid(AppError appError)
    {
        return new ErrorResult
            { Errors = new List<AppError>(new[] { appError }), ErrorType = ErrorType.Invalid };
    }
    
    public static ErrorResult Invalid()
    {
        return new ErrorResult
            { Errors = new List<AppError>(), ErrorType = ErrorType.Invalid };
    }

    public static ErrorResult Invalid(IEnumerable<AppError> appErrors)
    {
        return new ErrorResult { Errors = appErrors.ToList(), ErrorType = ErrorType.Invalid };
    }

    public static ErrorResult NotFound()
    {
        return new ErrorResult { Errors = Array.Empty<AppError>(), ErrorType = ErrorType.NotFound };
    }

    public static ErrorResult Forbidden()
    {
        return new ErrorResult { Errors = Array.Empty<AppError>(), ErrorType = ErrorType.Forbidden };
    }

    public static ErrorResult Unauthorized()
    {
        return new ErrorResult { Errors = Array.Empty<AppError>(), ErrorType = ErrorType.Unauthorized };
    }

    public static ErrorResult Conflict()
    {
        return new ErrorResult { Errors = Array.Empty<AppError>(), ErrorType = ErrorType.Conflict };
    }
}