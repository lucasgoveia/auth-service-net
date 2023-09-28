using System.Security.Cryptography;
using System.Text;

namespace AuthService.Common.Security;

public interface IAesEncryptor
{
    Task<string> Encrypt(string plainText, string key, string iv);
    Task<string> Decrypt(string cipherText, string key, string iv);
}

public class AesEncryptor : IAesEncryptor
{
    public async Task<string> Encrypt(string plainText, string key, string iv)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key).Take(32).ToArray();
        aes.IV = Encoding.UTF8.GetBytes(iv).Take(16).ToArray();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var ms = new MemoryStream();
        await using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            await using (var sw = new StreamWriter(cs))
            {
                await sw.WriteAsync(plainText);
            }
        }
        
        return Convert.ToBase64String(ms.ToArray());
    }
    
    public async Task<string> Decrypt(string cipherText, string key, string iv)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key).Take(32).ToArray();
        aes.IV = Encoding.UTF8.GetBytes(iv).Take(16).ToArray();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        await using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
        await using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);

        return await sr.ReadToEndAsync();
    }
}