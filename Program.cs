using System.Security.Claims;
using System.Threading.RateLimiting;
using AuthDemo.Data;
using AuthDemo.Security;
using AuthDemo.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// ---- Kestrel: hide server banner, tiny request bodies (this API only receives small JSON)
builder.WebHost.ConfigureKestrel(o =>
{
    o.AddServerHeader = false;
    o.Limits.MaxRequestBodySize = 16 * 1024;
});

// ---- Database (connection string comes from user-secrets / environment, NOT from appsettings.json)
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException(
        "Missing connection string. Run: dotnet user-secrets set \"ConnectionStrings:Default\" \"Host=localhost;Database=authdemo;Username=postgres;Password=YOUR_PASSWORD\"");

builder.Services.AddDbContext<AppDb>(o => o.UseNpgsql(connectionString));

builder.Services.AddControllers();

// ---- E-mail (used to send the registration code). Real SMTP in production, console in development.
var smtp = builder.Configuration.GetSection("Smtp").Get<SmtpOptions>();
if (smtp is not null && !string.IsNullOrWhiteSpace(smtp.Host))
{
    if (string.IsNullOrWhiteSpace(smtp.FromAddress))
        throw new InvalidOperationException("Smtp:FromAddress is required when Smtp:Host is set.");

    builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
    builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
}
else if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
}
else
{
    throw new InvalidOperationException("SMTP is not configured. Set the Smtp:* settings (see README).");
}
builder.Services.AddProblemDetails(); // one consistent JSON error shape for every error

// ---- Authentication: HttpOnly cookie issued by the server (JavaScript can never read it)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
    {
        o.Cookie.Name = "__Host-auth";                       // __Host- prefix: Secure, Path=/, no Domain
        o.Cookie.HttpOnly = true;                            // not readable by scripts (XSS can't steal it)
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;   // HTTPS only
        o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;             // never sent from other sites (CSRF defence)
        o.Cookie.Path = "/";
        o.Cookie.IsEssential = true;

        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = false;                         // hard 8h limit

        // APIs answer 401/403, they don't redirect to a login page
        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
        o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };

        // Runs on every request: the server decides if this cookie is still valid.
        // Deleted user, rotated SecurityStamp (logout) or changed role => cookie is rejected.
        o.Events.OnValidatePrincipal = async ctx =>
        {
            var principal = ctx.Principal;
            var stamp = principal?.FindFirstValue(SessionClaims.Stamp);
            var role = principal?.FindFirstValue(ClaimTypes.Role);
            var valid = false;

            if (int.TryParse(principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) && stamp is not null)
            {
                var db = ctx.HttpContext.RequestServices.GetRequiredService<AppDb>();
                var current = await db.Users.AsNoTracking()
                    .Where(u => u.Id == userId)
                    .Select(u => new { u.SecurityStamp, u.Role })
                    .FirstOrDefaultAsync(ctx.HttpContext.RequestAborted);

                valid = current is not null && current.SecurityStamp == stamp && current.Role == role;
            }

            if (!valid)
            {
                ctx.RejectPrincipal();
                await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        };
    });

// ---- Authorization: secure by default. Every endpoint needs a login unless it has [AllowAnonymous]
builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});

// ---- Rate limiting (per client IP)
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    static string Ip(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    // login, register, delete account: 10 requests / minute
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(Ip(ctx), _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = 10,
        Window = TimeSpan.FromMinutes(1),
        QueueLimit = 0
    }));

    // everything else: 120 requests / minute
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        RateLimitPartition.GetFixedWindowLimiter(Ip(ctx), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 120,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));

    o.OnRejected = (ctx, ct) =>
    {
        if (ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            ctx.HttpContext.Response.Headers[HeaderNames.RetryAfter] = ((int)retryAfter.TotalSeconds).ToString();

        return new ValueTask(ctx.HttpContext.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = StatusCodes.Status429TooManyRequests,
            Title = "Too many requests",
            Detail = "Too many requests. Please wait a minute and try again."
        }, ct));
    };
});

var app = builder.Build();

await DbInitializer.InitializeAsync(
    app.Services.CreateScope().ServiceProvider,
    app.Configuration,
    app.Logger);

// ---- Pipeline (order matters)
app.UseExceptionHandler();                       // unhandled errors -> generic ProblemDetails, no stack traces
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

// Security headers
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h["Cross-Origin-Opener-Policy"] = "same-origin";
    h["Cross-Origin-Resource-Policy"] = "same-origin";

    // never let browsers or proxies cache account data
    if (ctx.Request.Path.StartsWithSegments("/api"))
        h["Cache-Control"] = "no-store";

    await next();
});

app.UseStatusCodePages();                        // empty 401/403/404/... responses get a ProblemDetails body
app.UseDefaultFiles();                           // serves wwwroot/index.html at "/"
app.UseStaticFiles();
app.UseRouting();

// CSRF guard for the API. With SameSite=Strict this is a second layer:
//  1) the Origin header (when present) must be this very site
//  2) a custom header is required; other sites can't send it without a CORS preflight, and we allow no CORS
app.Use(async (ctx, next) =>
{
    var method = ctx.Request.Method;
    var isUnsafe = !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method));

    if (isUnsafe && ctx.Request.Path.StartsWithSegments("/api"))
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        var expected = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
        var originOk = origin.Length == 0 || string.Equals(origin, expected, StringComparison.OrdinalIgnoreCase);
        var headerOk = ctx.Request.Headers["X-Requested-With"].ToString() == "fetch";

        if (!originOk || !headerOk)
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Status = StatusCodes.Status403Forbidden,
                Title = "Forbidden",
                Detail = "Cross-site or malformed request blocked."
            });
            return;
        }
    }

    await next();
});

app.UseRateLimiter();
app.UseAuthentication(); // who are you?
app.UseAuthorization();  // what may you do?
app.MapControllers();
app.Run();
