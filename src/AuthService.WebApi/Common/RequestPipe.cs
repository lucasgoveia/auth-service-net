using AuthService.Common.Results;
using AuthService.WebApi.Common.ResultExtensions;
using FluentValidation;

namespace AuthService.WebApi.Common;

public class RequestPipe
{
    private readonly IServiceProvider _serviceProvider;

    public RequestPipe(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task<Result<TResponse>> Pipe<TRequest, TResponse>(TRequest request,
        Func<TRequest, CancellationToken, Task<Result<TResponse>>> next, CancellationToken ct = default)
    {
        var validator = _serviceProvider.GetService<IValidator<TRequest>>();

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
        var validator = _serviceProvider.GetService<IValidator<TRequest>>();

        if (validator is not null)
        {
            var validationResult = await validator.ValidateAsync(request, ct);

            if (!validationResult.IsValid)
                return validationResult.ToErrorResult();
        }

        return await next(request, ct);
    }
}