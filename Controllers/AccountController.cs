using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthDemo.Data;
using AuthDemo.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.Controllers;

public class DeleteAccountDto
{
    [Required, StringLength(128)] public string Password { get; set; } = "";
}

[ApiController]
[Route("api/account")]
[Authorize] // every action requires a valid auth cookie -> otherwise 401
public class AccountController(AppDb db) : ControllerBase
{
    // The id ALWAYS comes from the server-issued cookie, never from the URL or request body
    private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == CurrentUserId);
        return u is null
            ? Unauthorized()
            : Ok(new { name = u.Name, email = u.Email, role = u.Role, createdAt = u.CreatedAt });
    }

    // Destructive action => re-authenticate with the password. Only YOUR OWN account can be deleted.
    [HttpDelete]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Delete(DeleteAccountDto dto)
    {
        var user = await db.Users.FirstOrDefaultAsync(x => x.Id == CurrentUserId);
        if (user is null) return Unauthorized();

        if (!PasswordPolicy.Verify(dto.Password, user.PasswordHash))
            return Problem(detail: "Incorrect password.", statusCode: StatusCodes.Status400BadRequest);

        db.Users.Remove(user);
        await db.SaveChangesAsync();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return NoContent();
    }

    // Role is enforced here on the server; the button in the UI is only a convenience
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly() => Ok(new { message = "Hello, admin!" });
}
