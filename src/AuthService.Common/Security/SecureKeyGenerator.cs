using System.Security.Cryptography;

namespace AuthService.Common.Security;

public interface ISecureKeyGenerator
{
    string Generate(char[] alphabet, int keyLength);
}

public class SecureKeyGenerator : ISecureKeyGenerator
{
    public string Generate(char[] alphabet, int keyLength)
    {
        var randomChars = Enumerable.Range(0, keyLength)
            .Select(_ => RandomNumberGenerator.GetInt32(0, alphabet.Length))
            .Select(i => alphabet[i])
            .ToArray();

        return new string(randomChars);
    }
}