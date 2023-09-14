namespace AuthService.WebApi.Common.Security;

using BCrypt.Net;

public class PasswordHasher : IPasswordHasher
{
    private const int WorkFactor = 12;
    
    public string Hash(string password)
    {
        return BCrypt.HashPassword(password, WorkFactor);
    }

    public bool Verify(string password, string hash)
    {
        return BCrypt.Verify(password, hash);
    }
}