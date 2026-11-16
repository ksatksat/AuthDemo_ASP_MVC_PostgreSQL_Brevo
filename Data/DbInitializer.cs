using AuthDemo.Models;
using AuthDemo.Security;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace AuthDemo.Data;

public static class DbInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, IConfiguration config, ILogger logger)
    {
        var db = services.GetRequiredService<AppDb>();

        // Real migrations when they exist (dotnet ef migrations add InitialCreate),
        // otherwise create the schema directly so the demo works out of the box.
        if (db.Database.GetMigrations().Any())
        {
            await db.Database.MigrateAsync();
        }
        else
        {
            await db.Database.EnsureCreatedAsync();

            // EnsureCreated does nothing when the database already has tables (e.g. made by an older version)
            try
            {
                await db.EmailVerifications.AsNoTracking().AnyAsync();
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UndefinedTable)
            {
                throw new InvalidOperationException(
                    "The database schema is outdated (table EmailVerifications is missing). " +
                    "Drop and recreate the 'authdemo' database, or use EF migrations (see README).", ex);
            }
        }

        // Optional first admin, read from user-secrets / environment variables (never from client input)
        var email = config["SeedAdmin:Email"]?.Trim().ToLowerInvariant();
        var password = config["SeedAdmin:Password"];
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) return;

        var error = PasswordPolicy.Validate(password);
        if (error is not null)
        {
            logger.LogWarning("SeedAdmin skipped: {Error}", error);
            return;
        }

        if (await db.Users.AnyAsync(u => u.Email == email)) return;

        db.Users.Add(new User
        {
            Name = "Admin",
            Email = email,
            PasswordHash = PasswordPolicy.Hash(password),
            Role = "Admin"
        });
        await db.SaveChangesAsync();
        logger.LogInformation("Seeded admin account {Email}.", email);
    }
}
