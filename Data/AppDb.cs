using AuthDemo.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.Data;

public class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<EmailVerification> EmailVerifications => Set<EmailVerification>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.Name).HasMaxLength(50).IsRequired();
            e.Property(u => u.Email).HasMaxLength(254).IsRequired();
            e.Property(u => u.PasswordHash).HasMaxLength(100).IsRequired();
            e.Property(u => u.Role).HasMaxLength(20).IsRequired();
            e.Property(u => u.SecurityStamp).HasMaxLength(32).IsRequired();
            e.Property(u => u.CreatedAt).HasColumnType("timestamp with time zone");
            e.Property(u => u.LockoutEnd).HasColumnType("timestamp with time zone");
        });

        b.Entity<EmailVerification>(e =>
        {
            e.HasIndex(v => v.Email).IsUnique();
            e.Property(v => v.Email).HasMaxLength(254).IsRequired();
            e.Property(v => v.CodeHash).HasMaxLength(64);
            e.Property(v => v.ExpiresAt).HasColumnType("timestamp with time zone");
            e.Property(v => v.LastSentAt).HasColumnType("timestamp with time zone");
        });
    }
}
