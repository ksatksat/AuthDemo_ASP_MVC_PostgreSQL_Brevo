using System.Text;
using System.Text.RegularExpressions;

namespace AuthDemo.Security;

public static class PasswordPolicy
{
    private const int WorkFactor = 12;
    private const int MaxBytes = 72; // BCrypt silently ignores everything after 72 bytes

    // min 8 chars: 1 lowercase, 1 UPPERCASE, 1 digit, 1 special char
    private static readonly Regex Strong = new(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    // Used to spend the same time when the e-mail does not exist (prevents timing-based user discovery)
    private static readonly string DummyHash =
        BCrypt.Net.BCrypt.HashPassword("dummy-password-for-timing-only", WorkFactor);

    /// <summary>Returns an error message, or null when the password is acceptable.</summary>
    public static string? Validate(string password)
    {
        if (Encoding.UTF8.GetByteCount(password) > MaxBytes)
            return $"Password is too long (max {MaxBytes} bytes).";

        if (!Strong.IsMatch(password))
            return "Password must be 8+ chars with a-z, A-Z, 0-9 and a special character (e.g. _ or -).";

        return null;
    }

    public static string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

    public static bool Verify(string password, string hash) => BCrypt.Net.BCrypt.Verify(password, hash);

    public static void BurnTime(string password) => BCrypt.Net.BCrypt.Verify(password, DummyHash);
}
