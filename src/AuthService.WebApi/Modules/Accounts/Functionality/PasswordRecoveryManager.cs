using System.Runtime.CompilerServices;
using AuthService.Common.Caching;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.WebApi.Messages.Commands;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IPasswordRecoveryManager
{
    Task SendCode(string email);
    Task<bool> Verify(string email, string code);
    Task RevokeCode(string email);
}

public class PasswordRecoveryManager(IOtpGenerator otpGenerator,
        IPasswordRecoveryCodeRepository codeRepository, IPasswordHasher hasher, IMessageBus bus)
    : IPasswordRecoveryManager
{
    public async Task SendCode(string email)
    {
        var code = otpGenerator.Generate();
        var hashedCode = hasher.Hash(code);
        await bus.Publish(new SendPasswordRecovery { Email = email, Code = code, CodeExpirationMinutes = PasswordRecoveryCodeRepository.CodeExpirationMinutes });
        await codeRepository.Save(email, hashedCode);
    }

    public async Task<bool> Verify(string email, string code)
    {
        var savedHashedCode = await codeRepository.Get(email);

        if (savedHashedCode is null)
        {
            return false;
        }

        return hasher.Verify(code, savedHashedCode);
    }

    public Task RevokeCode(string email)
    {
        return codeRepository.Remove(email);
    }
}

public interface IPasswordRecoveryCodeRepository
{
    Task Save(string email, string token);
    Task<string?> Get(string email);
    Task Remove(string email);
}

public class PasswordRecoveryCodeRepository(ICacher cacher) : IPasswordRecoveryCodeRepository
{
    public const int CodeExpirationMinutes = 30;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildKey(string email) => $"accounts:password-recovery:{email}";

    public async Task Save(string email, string token)
    {
        await cacher.Set(BuildKey(email), token, TimeSpan.FromMinutes(CodeExpirationMinutes));
    }

    public async Task<string?> Get(string email)
    {
        return await cacher.Get<string>(BuildKey(email));
    }

    public Task Remove(string email)
    {
        return cacher.Remove(BuildKey(email));
    }
}