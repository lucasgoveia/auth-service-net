using System.Runtime.CompilerServices;
using AuthService.Common.Caching;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.WebApi.Messages.Commands;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IEmailVerificationManager
{
    Task SendCode(long userId, string email);
    Task<bool> Verify(long userId, string code);
    Task RevokeCode(long userId);
}

public class EmailVerificationManager : IEmailVerificationManager
{
    private readonly IEmailVerificationCodeRepository _codeRepository;
    private readonly IPasswordHasher _hasher;
    private readonly IMessageBus _bus;
    private readonly IOtpGenerator _otpGenerator;

    public EmailVerificationManager(IEmailVerificationCodeRepository codeRepository,
        IPasswordHasher hasher, IMessageBus bus, IOtpGenerator otpGenerator)
    {
        _codeRepository = codeRepository;
        _hasher = hasher;
        _bus = bus;
        _otpGenerator = otpGenerator;
    }

    public async Task SendCode(long userId, string email)
    {
        var code = _otpGenerator.Generate();
        var hashedCode = _hasher.Hash(code);
        await _bus.Publish(new SendEmailVerification { Code = code, Email = email });
        await _codeRepository.Save(userId, hashedCode);
    }


    public async Task<bool> Verify(long userId, string code)
    {
        var savedHashedCode = await _codeRepository.Get(userId);

        if (savedHashedCode is null)
        {
            return false;
        }

        return _hasher.Verify(code, savedHashedCode);
    }

    public Task RevokeCode(long userId)
    {
        return _codeRepository.Remove(userId);
    }
}

public interface IEmailVerificationCodeRepository
{
    Task Save(long accountId, string hashedCode);
    Task<string?> Get(long accountId);
    Task Remove(long accountId);
}

public class EmailVerificationCodeRepository : IEmailVerificationCodeRepository
{
    private readonly ICacher _cacher;

    public EmailVerificationCodeRepository(ICacher cacher)
    {
        _cacher = cacher;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildKey(long accountId) => $"accounts:email-verification:{accountId}";

    public async Task Save(long accountId, string hashedCode)
    {
        var key = BuildKey(accountId);
        await _cacher.Set(key, hashedCode, TimeSpan.FromMinutes(30));
    }

    public async Task<string?> Get(long accountId)
    {
        return await _cacher.Get<string>(BuildKey(accountId));
    }

    public Task Remove(long accountId)
    {
        return _cacher.Remove(BuildKey(accountId));
    }
}