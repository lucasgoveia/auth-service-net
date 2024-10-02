using System.Runtime.CompilerServices;
using AuthService.Common.Caching;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.WebApi.Messages.Commands;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IEmailVerificationManager
{
    Task SendCode(SnowflakeId userId, string email);
    Task<bool> Verify(SnowflakeId userId, string code);
    Task RevokeCode(SnowflakeId userId);
}

public class EmailVerificationManager(IEmailVerificationCodeRepository codeRepository,
        IPasswordHasher hasher, IMessageBus bus, IOtpGenerator otpGenerator)
    : IEmailVerificationManager
{
    public async Task SendCode(SnowflakeId userId, string email)
    {
        var code = otpGenerator.Generate();
        var hashedCode = hasher.Hash(code);
        await bus.Publish(new SendEmailVerification { Code = code, Email = email });
        await codeRepository.Save(userId, hashedCode);
    }


    public async Task<bool> Verify(SnowflakeId userId, string code)
    {
        var savedHashedCode = await codeRepository.Get(userId);

        if (savedHashedCode is null)
        {
            return false;
        }

        return hasher.Verify(code, savedHashedCode);
    }

    public Task RevokeCode(SnowflakeId userId)
    {
        return codeRepository.Remove(userId);
    }
}

public interface IEmailVerificationCodeRepository
{
    Task Save(SnowflakeId accountId, string hashedCode);
    Task<string?> Get(SnowflakeId accountId);
    Task Remove(SnowflakeId accountId);
}

public class EmailVerificationCodeRepository : IEmailVerificationCodeRepository
{
    private readonly ICacher _cacher;

    public EmailVerificationCodeRepository(ICacher cacher)
    {
        _cacher = cacher;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildKey(SnowflakeId accountId) => $"accounts:email-verification:{accountId}";

    public async Task Save(SnowflakeId accountId, string hashedCode)
    {
        var key = BuildKey(accountId);
        await _cacher.Set(key, hashedCode, TimeSpan.FromMinutes(30));
    }

    public async Task<string?> Get(SnowflakeId accountId)
    {
        return await _cacher.Get<string>(BuildKey(accountId));
    }

    public Task Remove(SnowflakeId accountId)
    {
        return _cacher.Remove(BuildKey(accountId));
    }
}