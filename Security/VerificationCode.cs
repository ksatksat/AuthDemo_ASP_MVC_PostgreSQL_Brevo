using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthDemo.Security;

public static class VerificationCode
{
    /// <summary>Cryptographically random 6-digit code, e.g. "042917".</summary>
    public static string Generate() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    public static string Hash(string email, string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{email}:{code}")));

    public static bool Matches(string email, string code, string storedHash) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(Hash(email, code)),
            Encoding.UTF8.GetBytes(storedHash));
}

public static class EmailRules
{
    // Strict on purpose: one @, no spaces or quotes, a real-looking domain with a dot and a 2+ letter TLD
    private static readonly Regex Pattern = new(
        @"^[^@\s<>""',;:]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    public static bool IsValid(string email) => email.Length <= 254 && Pattern.IsMatch(email);
}
