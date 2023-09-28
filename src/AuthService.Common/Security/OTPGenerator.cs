namespace AuthService.Common.Security;

public interface IOtpGenerator
{
    string Generate();
}

public class OtpGenerator : IOtpGenerator
{
    public static readonly char[] Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    public const int CodeLength = 6;

    private readonly ISecureKeyGenerator _keyGenerator;

    public OtpGenerator(ISecureKeyGenerator keyGenerator)
    {
        _keyGenerator = keyGenerator;
    }

    public string Generate() => _keyGenerator.Generate(Alphabet, CodeLength);
}