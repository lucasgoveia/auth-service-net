using Fluid;
using Mjml.Net;

namespace AuthService.EmailTemplating;

public static class TemplateEmailRenderer
{
    public static (string Subject, string Body) Render(this EmailTemplate template, object? bodyData, object? subjectData = null)
    {
        var emailSubject = subjectData is null 
            ? template.Subject
            : Render(template.Subject, subjectData);
        
        var emailBodyMjml = bodyData is null 
            ? template.Body
            : Render(template.Body, bodyData);
        
        var mjmlRenderer = new MjmlRenderer();
        var emailBody = mjmlRenderer.Render(emailBodyMjml).Html;

        return (emailSubject, emailBody);
    }

    private static string Render(string subject, object? subjectData)
    {
        var parser = new FluidParser();
        
        var template = parser.Parse(subject);
        var context = new TemplateContext(subjectData);
        return template.Render(context);
    }
}