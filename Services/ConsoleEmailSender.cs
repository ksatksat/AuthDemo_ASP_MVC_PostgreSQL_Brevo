namespace AuthDemo.Services;

// DEVELOPMENT ONLY: used when no SMTP server is configured. Prints the e-mail to the console.
public class ConsoleEmailSender(ILogger<ConsoleEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        logger.LogWarning("DEV ONLY - no SMTP configured, e-mail NOT sent.\nTo: {To}\nSubject: {Subject}\n{Body}",
            to, subject, body);
        return Task.CompletedTask;
    }
}
