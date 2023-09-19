using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using AuthService.Messages.Commands;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Messaging;
using AuthService.WebApi.Common.Security;
using MassTransit;

namespace AuthService.WebApi.Modules.Accounts.Functionality;

public interface IEmailVerificationManager
{
    Task SendCode(long accountId, string email);
    Task<bool> Verify(long accountId, string code);
}

public class EmailVerificationManager : IEmailVerificationManager
{
    private readonly IEmailVerificationCodeGenerator _codeGenerator;
    private readonly IEmailVerificationCodeSender _codeSender;
    private readonly IEmailVerificationCodeRepository _codeRepository;
    private readonly IPasswordHasher _hasher;

    public EmailVerificationManager(IEmailVerificationCodeGenerator codeGenerator,
        IEmailVerificationCodeSender codeSender, IEmailVerificationCodeRepository codeRepository,
        IPasswordHasher hasher)
    {
        _codeGenerator = codeGenerator;
        _codeSender = codeSender;
        _codeRepository = codeRepository;
        _hasher = hasher;
    }

    public async Task SendCode(long accountId, string email)
    {
        var code = _codeGenerator.Generate();
        var hashedCode = _hasher.Hash(code);
        await _codeSender.Send(email, code);
        await _codeRepository.Save(accountId, hashedCode);
    }


    public async Task<bool> Verify(long accountId, string code)
    {
        var savedHashedCode = await _codeRepository.Get(accountId);

        if (savedHashedCode is null)
        {
            return false;
        }

        return _hasher.Verify(code, savedHashedCode);
    }
}

public interface IEmailVerificationCodeRepository
{
    Task Save(long accountId, string hashedCode);
    Task<string?> Get(long accountId);
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
}

public interface IEmailVerificationCodeSender
{
    Task Send(string email, string code, CancellationToken ct = default);
}

public class EmailVerificationCodeSender : IEmailVerificationCodeSender
{
    private readonly IMessageBus _bus;

    public EmailVerificationCodeSender(IMessageBus bus)
    {
        _bus = bus;
    }

    public async Task Send(string email, string code, CancellationToken ct = default)
    {
        await _bus.Publish(new SendEmailVerification { Code = code, Email = email }, ct);
    }
}

public interface IEmailVerificationCodeGenerator
{
    string Generate();
}

public class EmailVerificationCodeGenerator : IEmailVerificationCodeGenerator
{
    private readonly char[] _alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    
    public string Generate()
    {
        var randomChars = Enumerable.Range(0,6)
            .Select(_ => RandomNumberGenerator.GetInt32(0, _alphabet.Length))
            .Select(i => _alphabet[i])
            .ToArray();

        return new string(randomChars);
    }
}