using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public class RsaKeyHolder
{
    private readonly RSA _publicKey;
    private readonly RSA _privateKey;
    
    public RsaKeyHolder(IOptions<JwtConfig> jwtConfig)
    {
        var privateKeyBytes = Convert.FromBase64String(jwtConfig.Value.AccessTokenPrivateKey);
        var publicKeyBytes = Convert.FromBase64String(jwtConfig.Value.AccessTokenPublicKey);
        
        var privateRsa = RSA.Create(4096);
        privateRsa.ImportRSAPrivateKey(privateKeyBytes, out _);
        _privateKey = privateRsa;
        
        var publicRsa = RSA.Create(4096);
        publicRsa.ImportRSAPublicKey(publicKeyBytes, out _);
        _publicKey = publicRsa;
    }

    public RsaSecurityKey GetPublicKey()
    {
        return new RsaSecurityKey(_publicKey);
    }
    
    public RsaSecurityKey GetPrivateKey()
    {
        return new RsaSecurityKey(_privateKey);
    }
}