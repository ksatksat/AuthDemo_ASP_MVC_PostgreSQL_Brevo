using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthDemo.Data;
using AuthDemo.Models;
using AuthDemo.Security;
using AuthDemo.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace AuthDemo.Controllers;

// DTOs contain ONLY what the client may send. There is no Role property => no mass assignment.
public class SendCodeDto
{
    [Required, StringLength(254)] public string Email { get; set; } = "";
}

public class RegisterDto
{
    [Required, StringLength(254)] public string Email { get; set; } = "";
    [Required, RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits.")] public string Code { get; set; } = "";
    [Required, StringLength(50, MinimumLength = 2)] public string Name { get; set; } = "";
    [Required, StringLength(128)] public string Password { get; set; } = "";
}

public class LoginDto
{
    [Required, StringLength(254)] public string Email { get; set; } = "";
    [Required, StringLength(128)] public string Password { get; set; } = "";
}

[ApiController]
[AllowAnonymous]
[Route("api/auth")]
public class AuthController(AppDb db, IEmailSender emailSender, ILogger<AuthController> logger) : ControllerBase
{
    // Login protection
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    // E-mail code protection
    private const int MaxCodeAttempts = 5;                                   // wrong guesses per code
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);

    // STEP 1: "send me a code". The answer is always the same, so nobody can use this
    // endpoint to find out which e-mails already have an account.
    [HttpPost("send-code")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> SendCode(SendCodeDto dto)
    {
        var email = NormalizeEmail(dto.Email);
        if (!EmailRules.IsValid(email))
            return Problem(detail: "Please enter a valid email address.", statusCode: StatusCodes.Status400BadRequest);

        var now = DateTime.UtcNow;

        // housekeeping: forget requests older than a day
        await db.EmailVerifications.Where(v => v.LastSentAt < now.AddDays(-1)).ExecuteDeleteAsync();

        var row = await db.EmailVerifications.FirstOrDefaultAsync(v => v.Email == email);

        // Cooldown per address: nobody can flood a mailbox, from any number of IPs
        if (row is not null && now - row.LastSentAt < ResendCooldown)
            return CodeRequested();

        if (row is null)
        {
            row = new EmailVerification { Email = email };
            db.EmailVerifications.Add(row);
        }
        row.LastSentAt = now;
        row.Attempts = 0;

        string subject, body;
        if (await db.Users.AnyAsync(u => u.Email == email))
        {
            // Already registered: no code, just a notice to the real owner of the mailbox
            row.CodeHash = null;
            row.ExpiresAt = null;
            subject = "AuthDemo: you already have an account";
            body = "Someone (hopefully you) tried to register with this email address, " +
                   "but an account already exists.\n\nIf it was you, just log in. " +
                   "If it was not you, you can ignore this email.";
        }
        else
        {
            var code = VerificationCode.Generate();
            row.CodeHash = VerificationCode.Hash(email, code);
            row.ExpiresAt = now + CodeLifetime;
            subject = "Your AuthDemo verification code";
            body = $"Your verification code is: {code}\n\n" +
                   $"It expires in {(int)CodeLifetime.TotalMinutes} minutes. " +
                   "If you did not request it, you can ignore this email.";
        }

        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            return CodeRequested(); // two requests for the same address at the same moment
        }

        SendInBackground(email, subject, body);
        return CodeRequested();
    }

    // STEP 2: code + name + password. The account is created only now, by whoever holds the code,
    // so nobody can pre-register someone else's e-mail with a password of their own.
    [HttpPost("register")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var name = dto.Name.Trim();
        if (name.Length < 2 || name.Any(char.IsControl))
            return Problem(detail: "Name is invalid.", statusCode: StatusCodes.Status400BadRequest);

        var email = NormalizeEmail(dto.Email);
        if (!EmailRules.IsValid(email))
            return Problem(detail: "Please enter a valid email address.", statusCode: StatusCodes.Status400BadRequest);

        var passwordError = PasswordPolicy.Validate(dto.Password);
        if (passwordError is not null)
            return Problem(detail: passwordError, statusCode: StatusCodes.Status400BadRequest);

        var now = DateTime.UtcNow;
        var row = await db.EmailVerifications.FirstOrDefaultAsync(v => v.Email == email);

        // Unknown address, existing account, no active code, expired or burnt code: all look the same
        if (row is null || row.CodeHash is null || row.ExpiresAt is null
            || row.ExpiresAt < now || row.Attempts >= MaxCodeAttempts)
            return InvalidCode();

        if (!VerificationCode.Matches(email, dto.Code, row.CodeHash))
        {
            row.Attempts++;
            if (row.Attempts >= MaxCodeAttempts)
            {
                row.CodeHash = null; // too many wrong guesses: this code is dead, request a new one
                row.ExpiresAt = null;
            }
            await db.SaveChangesAsync();
            return InvalidCode();
        }

        var user = new User
        {
            Name = name,
            Email = email,
            PasswordHash = PasswordPolicy.Hash(dto.Password)
            // Role stays "User": it can never come from the request
        };
        db.Users.Add(user);
        db.EmailVerifications.Remove(row); // the code works only once

        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            return InvalidCode();
        }

        await SignInAsync(user);
        return Ok(UserResponse(user));
    }

    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        var email = NormalizeEmail(dto.Email);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
        var now = DateTime.UtcNow;

        // Unknown e-mail or locked account: same time, same message as a wrong password
        if (user is null || (user.LockoutEnd is { } until && until > now))
        {
            PasswordPolicy.BurnTime(dto.Password);
            return InvalidLogin();
        }

        if (!PasswordPolicy.Verify(dto.Password, user.PasswordHash))
        {
            user.FailedLoginCount++;
            if (user.FailedLoginCount >= MaxFailedAttempts)
            {
                user.LockoutEnd = now + LockoutDuration;
                user.FailedLoginCount = 0;
                logger.LogWarning("User {UserId} locked out after repeated failed logins.", user.Id);
            }
            await db.SaveChangesAsync();
            return InvalidLogin();
        }

        user.FailedLoginCount = 0;
        user.LockoutEnd = null;
        await db.SaveChangesAsync();

        await SignInAsync(user);
        return Ok(UserResponse(user));
    }

    // Server-side logout: rotating the stamp invalidates the cookie everywhere, even a stolen copy.
    // (It also signs the account out of all other browsers/devices.)
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        if (int.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            var newStamp = Guid.NewGuid().ToString("N");
            await db.Users.Where(u => u.Id == userId)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.SecurityStamp, newStamp));
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return NoContent();
    }

    private async Task SignInAsync(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, user.Role),
            new(SessionClaims.Stamp, user.SecurityStamp)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false }); // session cookie
    }

    // E-mails are sent in the background so the response time never reveals whether a mail was sent
    private void SendInBackground(string to, string subject, string body)
    {
        _ = Task.Run(async () =>
        {
            try { await emailSender.SendAsync(to, subject, body); }
            catch (Exception ex) { logger.LogError(ex, "Failed to send an e-mail."); }
        });
    }

    private IActionResult CodeRequested() =>
        Accepted(new { message = "If this address can be registered, a 6-digit code is on its way. Check your inbox and spam folder." });

    private IActionResult InvalidCode() =>
        Problem(detail: "Invalid or expired code. Please request a new one.", statusCode: StatusCodes.Status400BadRequest);

    private IActionResult InvalidLogin() =>
        Problem(detail: "Invalid email or password, or the account is temporarily locked.",
                statusCode: StatusCodes.Status401Unauthorized);

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static object UserResponse(User u) => new { name = u.Name, email = u.Email, role = u.Role };
}
