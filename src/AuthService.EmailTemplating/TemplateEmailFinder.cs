using System.Reflection;

namespace AuthService.EmailTemplating;

public static class TemplateEmailFinder
{
    private static readonly IDictionary<Templates, string> TemplateTypeFilenameMapper =
        new Dictionary<Templates, string>
        {
            { Templates.EmailVerification, "verification-email.mjml" },
            { Templates.PasswordRecovery, "password-recovery.mjml" }
        };

    private static readonly IDictionary<Templates, string> TemplateTypeSubjectMapper = new Dictionary<Templates, string>
    {
        { Templates.EmailVerification, "Account verification" },
        { Templates.PasswordRecovery, "Reset your password" }
    };

    public static EmailTemplate GetTemplate(Templates templateType)
    {
        var subject = TemplateTypeSubjectMapper[templateType];
        var body = GetTemplateFromResources(templateType);

        return new EmailTemplate(subject, body);
    }

    public static string GetTemplateFromResources(Templates templateType)
    {
        var templateFilename = TemplateTypeFilenameMapper[templateType];

        var assembly = Assembly.GetExecutingAssembly();
        var resources = assembly.GetManifestResourceNames();

        var templatePath = resources.First(x => x.EndsWith(templateFilename));

        using var stream = assembly.GetManifestResourceStream(templatePath);
        using var reader = new StreamReader(stream!);
        return reader.ReadToEnd();
    }
}

public record EmailTemplate(string Subject, string Body);