using FluentValidation;
using LucasGoveia.Results;
using LucasGoveia.Results.FluentValidation;

namespace AuthService.WebApi.Common;

public class RequestPipe(IServiceProvider serviceProvider)
{
    public async Task<Result<TResponse>> Pipe<TRequest, TResponse>(TRequest request,
        Func<TRequest, CancellationToken, Task<Result<TResponse>>> next, CancellationToken ct = default)
    {
        var validator = serviceProvider.GetService<IValidator<TRequest>>();

        if (validator is not null)
        {
            var validationResult = await validator.ValidateAsync(request, ct);

            if (!validationResult.IsValid)
                return validationResult.ToErrorResult();
        }

        return await next(request, ct);
    }

    public async Task<Result> Pipe<TRequest>(TRequest request, Func<TRequest, CancellationToken, Task<Result>> next,
        CancellationToken ct = default)
    {
        var validator = serviceProvider.GetService<IValidator<TRequest>>();

        if (validator is not null)
        {
            var validationResult = await validator.ValidateAsync(request, ct);

            if (!validationResult.IsValid)
                return validationResult.ToErrorResult();
        }

        return await next(request, ct);
    }
}