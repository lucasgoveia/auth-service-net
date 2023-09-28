using System.Net;
using AuthService.Common.Results;

namespace AuthService.WebApi.Common.ResultExtensions;

public static class ResultMinimalApiExtensions
{
    public static IResult ToApiResult<T>(this Result<T> result)
    {
        return result.Match(
            success => success.ToApiResult(),
            error => error.ToApiResult()
        );
    }

    public static IResult ToApiResult(this ErrorResult result)
    {
        return result.ErrorType switch
        {
            ErrorType.Error => TypedResults.StatusCode((int)HttpStatusCode.InternalServerError),
            ErrorType.Forbidden => TypedResults.Forbid(),
            ErrorType.Unauthorized => TypedResults.Unauthorized(),
            ErrorType.Invalid => TypedResults.BadRequest(result.Errors),
            ErrorType.NotFound => TypedResults.NotFound(),
            ErrorType.Conflict => TypedResults.Conflict(),
            _ => throw new InvalidOperationException(),
        };
    }

    public static IResult ToApiResult<T>(this SuccessResult<T> result)
    {
        return TypedResults.Ok(result.Value);
    }
}