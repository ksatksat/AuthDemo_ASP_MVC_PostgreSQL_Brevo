namespace AuthDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";         // stored lowercase, unique
    public string PasswordHash { get; set; } = "";  // BCrypt, never the raw password
    public string Role { get; set; } = "User";      // never set from client input

    // Changing this value invalidates every cookie issued before (server-side session revocation)
    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");

    // Brute-force protection
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEnd { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
