using System.Runtime.CompilerServices;
using AuthService.Common.Caching;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.WebApi.Messages.Commands;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IPasswordRecoveryManager
{
    Task SendCode(long userId, string email);
    Task<bool> Verify(long userId, string code);
    Task RevokeCode(long userId);
}

public class PasswordRecoveryManager : IPasswordRecoveryManager
{
    private readonly IOtpGenerator _otpGenerator;
    private readonly IPasswordRecoveryCodeRepository _codeRepository;
    private readonly IPasswordHasher _hasher;
    private readonly IMessageBus _bus;

    public PasswordRecoveryManager(IOtpGenerator otpGenerator,
        IPasswordRecoveryCodeRepository codeRepository, IPasswordHasher hasher, IMessageBus bus)
    {
        _otpGenerator = otpGenerator;
        _codeRepository = codeRepository;
        _hasher = hasher;
        _bus = bus;
    }

    public async Task SendCode(long userId, string email)
    {
        var code = _otpGenerator.Generate();
        var hashedCode = _hasher.Hash(code);
        await _bus.Publish(new SendPasswordRecovery { Email = email, Code = code, CodeExpirationMinutes = PasswordRecoveryCodeRepository.CodeExpirationMinutes });
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

public interface IPasswordRecoveryCodeRepository
{
    Task Save(long userId, string token);
    Task<string?> Get(long userId);
    Task Remove(long userId);
}

public class PasswordRecoveryCodeRepository : IPasswordRecoveryCodeRepository
{
    private readonly ICacher _cacher;
    public const int CodeExpirationMinutes = 30;

    public PasswordRecoveryCodeRepository(ICacher cacher)
    {
        _cacher = cacher;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildKey(long userId) => $"accounts:password-recovery:{userId}";

    public async Task Save(long userId, string token)
    {
        await _cacher.Set(BuildKey(userId), token, TimeSpan.FromMinutes(CodeExpirationMinutes));
    }

    public async Task<string?> Get(long userId)
    {
        return await _cacher.Get<string>(BuildKey(userId));
    }

    public Task Remove(long userId)
    {
        return _cacher.Remove(BuildKey(userId));
    }
}