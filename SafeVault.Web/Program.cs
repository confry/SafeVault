using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http; // SameSiteMode, CookieSecurePolicy
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

// ===================== DB =====================
builder.Services.AddSingleton<SqliteConnection>(_ =>
{
    var conn = new SqliteConnection("Data Source=safedev.db;Cache=Shared");
    conn.Open();

    using var cmd = conn.CreateCommand();
    cmd.CommandText = """
        CREATE TABLE IF NOT EXISTS Users (
            UserID        INTEGER PRIMARY KEY AUTOINCREMENT,
            Username      TEXT    NOT NULL UNIQUE,
            Email         TEXT    NOT NULL,
            PasswordHash  TEXT    NOT NULL,
            Role          TEXT    NOT NULL DEFAULT 'User'
        );
        """;
    cmd.ExecuteNonQuery();

    return conn;
});

builder.Services.AddSingleton<Data.UserRepository>();

// ===================== Auth / RBAC =====================
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "safevault.auth";
        options.SlidingExpiration = true;

        // Endurecer cookie (en PROD usa Always para HTTPS)
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

        // Para APIs: devolver 401/403 (no redirigir)
        options.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
        options.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// ===================== Security Headers (GLOBAL) =====================
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=()";
    ctx.Response.Headers["X-Frame-Options"] = "DENY"; // refuerza frame-ancestors 'none' de CSP en HTML
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// ===================== Actividad 1: Validación + Queries Parametrizadas =====================
app.MapPost("/submit", async (UserInput input, SqliteConnection conn) =>
{
    var (ok, errors, clean) = Security.InputValidator.Validate(input);
    if (!ok) return Results.BadRequest(new { errors });

    using var insert = conn.CreateCommand();
    insert.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES ($u, $e, $ph, $r);";
    insert.Parameters.AddWithValue("$u", clean.Username);
    insert.Parameters.AddWithValue("$e", clean.Email);
    insert.Parameters.AddWithValue("$ph", BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString())); // dummy hash
    insert.Parameters.AddWithValue("$r", "User");

    try
    {
        await insert.ExecuteNonQueryAsync();
    }
    catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19) // UNIQUE constraint
    {
        return Results.Conflict(new { error = "Username ya existe." });
    }

    // JSON estructurado (no reflejar strings interpoladas)
    return Results.Ok(new { saved = true, username = clean.Username });
});

app.MapGet("/users/{username}", async (string username, SqliteConnection conn) =>
{
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT UserID, Username, Email, Role FROM Users WHERE Username = $u;";
    cmd.Parameters.AddWithValue("$u", username);

    using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.NotFound();

    return Results.Ok(new
    {
        UserID = r.GetInt64(0),
        Username = r.GetString(1),
        Email = r.GetString(2),
        Role = r.GetString(3)
    });
});

// ===================== Actividad 2: Auth & RBAC =====================
app.MapPost("/auth/register", async (Auth.RegisterInput input, Data.UserRepository repo) =>
{
    var (ok, errors) = Auth.AuthValidator.ValidateRegister(input);
    if (!ok) return Results.BadRequest(new { errors });

    var exists = await repo.GetByUsernameAsync(input.Username);
    if (exists is not null) return Results.Conflict(new { error = "Username ya existe." });

    var hash = BCrypt.Net.BCrypt.HashPassword(input.Password, workFactor: 12);
    await repo.CreateUserAsync(input.Username.Trim(), input.Email.Trim(), hash, input.Role?.Trim() ?? "User");
    return Results.Ok(new { message = "Usuario registrado." });
});

app.MapPost("/auth/login", async (Auth.LoginInput input, Data.UserRepository repo, HttpContext http) =>
{
    var (ok, errors) = Auth.AuthValidator.ValidateLogin(input);
    if (!ok) return Results.BadRequest(new { errors });

    var user = await repo.GetByUsernameAsync(input.Username.Trim());
    if (user is null || !BCrypt.Net.BCrypt.Verify(input.Password, user.Value.PasswordHash))
        return Results.Unauthorized();

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Value.UserID.ToString()),
        new Claim(ClaimTypes.Name, user.Value.Username),
        new Claim(ClaimTypes.Role, user.Value.Role)
    };

    var id = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));
    return Results.Ok(new { message = "Login OK", role = user.Value.Role });
});

app.MapPost("/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync();
    return Results.Ok(new { message = "Logout OK" });
});

app.MapGet("/admin/dashboard", (ClaimsPrincipal user) =>
{
    return Results.Ok(new { message = $"Bienvenido Admin {user.Identity?.Name}" });
})
.RequireAuthorization(policy => policy.RequireRole("Admin"));

app.MapGet("/me", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        name = user.Identity?.Name,
        role = user.FindFirstValue(ClaimTypes.Role)
    });
}).RequireAuthorization();

app.Run();

// ===================== Records / Validators =====================
public record UserInput(string Username, string Email);

namespace Security
{
    public static class InputValidator
    {
        private static readonly Regex UsernameRegex =
            new(@"^[A-Za-z0-9 _\.\-]{3,50}$", RegexOptions.Compiled);

        public static (bool ok, List<string> errors, UserInput clean) Validate(UserInput input)
        {
            var errors = new List<string>();
            var username = (input.Username ?? "").Trim();
            var email = (input.Email ?? "").Trim();

            if (!UsernameRegex.IsMatch(username))
                errors.Add("Username inválido. Use letras, números, espacio, punto o guion (3-50).");

            if (!new EmailAddressAttribute().IsValid(email))
                errors.Add("Email inválido.");

            if (ContainsHtmlOrScript(username) || ContainsHtmlOrScript(email))
                errors.Add("No se permiten etiquetas HTML ni scripts en los campos.");

            var clean = new UserInput(username, email);
            return (errors.Count == 0, errors, clean);
        }

        private static bool ContainsHtmlOrScript(string s) =>
            s.Contains('<') || s.Contains('>') ||
            Regex.IsMatch(s, @"(?i)<\s*script|on\w+\s*=");
    }
}

namespace Auth
{
    public record RegisterInput(string Username, string Email, string Password, string? Role);
    public record LoginInput(string Username, string Password);

    public static class AuthValidator
    {
        public static (bool ok, List<string> errors) ValidateRegister(RegisterInput input)
        {
            var errors = new List<string>();
            if (string.IsNullOrWhiteSpace(input.Username) || input.Username.Trim().Length < 3)
                errors.Add("Username mínimo 3 caracteres.");
            if (!new EmailAddressAttribute().IsValid(input.Email))
                errors.Add("Email inválido.");
            if (string.IsNullOrWhiteSpace(input.Password) || input.Password.Length < 8)
                errors.Add("Password mínimo 8 caracteres.");
            if (Regex.IsMatch(input.Username, @"[<>]") || Regex.IsMatch(input.Email, @"[<>]"))
                errors.Add("No se permiten < ni >");
            return (errors.Count == 0, errors);
        }

        public static (bool ok, List<string> errors) ValidateLogin(LoginInput input)
        {
            var errors = new List<string>();
            if (string.IsNullOrWhiteSpace(input.Username)) errors.Add("Username requerido.");
            if (string.IsNullOrWhiteSpace(input.Password)) errors.Add("Password requerido.");
            return (errors.Count == 0, errors);
        }
    }
}

// Necesario para WebApplicationFactory<Program> en tests
public partial class Program { }
