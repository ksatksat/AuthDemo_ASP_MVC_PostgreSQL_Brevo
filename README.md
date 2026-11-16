# AuthDemo - ASP.NET Core + PostgreSQL + cookie auth + e-mail verification (static HTML/CSS/JS)

## Registration flow (only real e-mails)
1. The visitor enters an e-mail and the server mails a 6-digit code (valid 10 minutes).
2. The visitor enters the code + name + password. The account is created only now,
   so an address that cannot read its mailbox can never register.

Protections: 5 wrong guesses kill the code, 1 mail per address per minute, 10 requests/min per IP,
codes are stored hashed and work once, the answer to "send code" is identical for new and existing
addresses (no e-mail enumeration).

## Run
1. Create an empty PostgreSQL database named `authdemo`
   (upgrading from the previous version? drop and recreate it: a new table was added).
2. Store secrets outside the code (run inside this folder):

       dotnet user-secrets set "ConnectionStrings:Default" "Host=localhost;Database=authdemo;Username=postgres;Password=YOUR_PASSWORD"
       dotnet user-secrets set "SeedAdmin:Email" "admin@example.com"
       dotnet user-secrets set "SeedAdmin:Password" "Admin_Pass-123"

3. SMTP, so real e-mails are sent (any provider: Brevo, Mailgun, SendGrid, Amazon SES, Gmail app password ...):

       dotnet user-secrets set "Smtp:Host" "smtp.your-provider.com"
       dotnet user-secrets set "Smtp:Port" "587"
       dotnet user-secrets set "Smtp:User" "your-smtp-login"
       dotnet user-secrets set "Smtp:Password" "your-smtp-password"
       dotnet user-secrets set "Smtp:FromAddress" "no-reply@your-domain.com"
       dotnet user-secrets set "Smtp:FromName" "AuthDemo"

   Without Smtp:Host the app runs ONLY in Development and prints the e-mail (with the code) in the console.
   In production it refuses to start without SMTP.
4. Trust the HTTPS dev certificate once: `dotnet dev-certs https --trust`
5. `dotnet run` and open https://localhost:7080 (the auth cookie is Secure, so use HTTPS).

## Migrations (recommended)
Without migrations the app creates the tables with EnsureCreated. To use real migrations:

    dotnet tool install --global dotnet-ef
    dotnet ef migrations add InitialCreate
    dotnet run        # applies pending migrations at startup

## Production checklist
- Send from a domain with SPF and DKIM set up, otherwise the codes land in spam.
- Set `AllowedHosts` to your real domain.
- Behind a reverse proxy: configure `UseForwardedHeaders` so rate limiting sees real client IPs
  and the CSRF Origin check sees the public scheme/host.
- Keep secrets in environment variables or a secret store, never in git.
