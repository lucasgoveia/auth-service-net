using FluentValidation.Results;

namespace AuthService.WebApi.Common.Result;

public static class FluentValidationExtensions
{
    public static ErrorResult ToErrorResult(this ValidationResult validationResult)
    {
        var errors = validationResult.Errors.Select(x => new AppError
        {
            ErrorCode = x.ErrorCode,
            ErrorMessage = x.ErrorMessage
        }).ToArray();

        return ErrorResult.Invalid(errors);
    }
}