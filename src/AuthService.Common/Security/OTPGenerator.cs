namespace AuthService.Common.Security;

public interface IOtpGenerator
{
    string Generate();
}

public class OtpGenerator(ISecureKeyGenerator keyGenerator) : IOtpGenerator
{
    private static readonly char[] Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    public const int CodeLength = 6;

    public string Generate() => keyGenerator.Generate(Alphabet, CodeLength);
}