namespace AuthDemo.Models;

// One row per e-mail address that asked for a registration code.
// No User exists until the person proves they can read this mailbox.
public class EmailVerification
{
    public int Id { get; set; }
    public string Email { get; set; } = "";       // normalized (trimmed, lowercase), unique
    public string? CodeHash { get; set; }         // SHA-256 of the code, never the code itself
    public DateTime? ExpiresAt { get; set; }
    public int Attempts { get; set; }             // wrong guesses for the current code
    public DateTime LastSentAt { get; set; }      // used for the resend cooldown
}
