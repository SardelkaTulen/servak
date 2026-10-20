
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MyServer.Data;
using MyServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("DefaultConnection")
        ?? "Data Source=myserver.db"));

builder.Services.AddScoped<IPasswordHasher<UserAccount>,
    PasswordHasher<UserAccount>>();

var app = builder.Build();

// Создаём таблицы базы данных, если их ещё нет.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
}

app.MapGet("/", () => "MyServer is running!");

// РЕГИСТРАЦИЯ
app.MapPost("/api/auth/register", async (
    RegisterRequest request,
    AppDbContext db,
    IPasswordHasher<UserAccount> hasher) =>
{
    var username = request.Username?.Trim();
    var email = request.Email?.Trim();
    var password = request.Password;

    if (string.IsNullOrWhiteSpace(username) ||
        string.IsNullOrWhiteSpace(email) ||
        string.IsNullOrEmpty(password))
    {
        return Results.BadRequest(new
        {
            message = "Заполни все поля."
        });
    }

    if (username.Length > 30 ||
        email.Length > 254 ||
        !email.Contains('@') ||
        email.Contains(' '))
    {
        return Results.BadRequest(new
        {
            message = "Некорректное имя или почта."
        });
    }

    if (password.Length < 8 || password.Length > 128)
    {
        return Results.BadRequest(new
        {
            message = "Пароль должен содержать от 8 до 128 символов."
        });
    }

    var normalizedEmail = email.ToUpperInvariant();

    if (await db.Users.AnyAsync(
        user => user.NormalizedEmail == normalizedEmail))
    {
        return Results.Conflict(new
        {
            message = "Эта почта уже зарегистрирована."
        });
    }

    var user = new UserAccount
    {
        Username = username,
        Email = email,
        NormalizedEmail = normalizedEmail
    };

    user.PasswordHash = hasher.HashPassword(user, password);

    db.Users.Add(user);

    try
    {
        await db.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        return Results.Conflict(new
        {
            message = "Аккаунт с такой почтой уже существует."
        });
    }

    return Results.Ok(new
    {
        message = "Аккаунт успешно создан!",
        username = user.Username
    });
});

// ВХОД
app.MapPost("/api/auth/login", async (
    LoginRequest request,
    AppDbContext db,
    IPasswordHasher<UserAccount> hasher) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) ||
        string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new
        {
            message = "Введи почту и пароль."
        });
    }

    var email = request.Email.Trim().ToUpperInvariant();

    var user = await db.Users.SingleOrDefaultAsync(
        item => item.NormalizedEmail == email);

    if (user is null)
    {
        return Results.Json(
            new { message = "Неверная почта или пароль." },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var result = hasher.VerifyHashedPassword(
        user, user.PasswordHash, request.Password);

    if (result == PasswordVerificationResult.Failed)
    {
        return Results.Json(
            new { message = "Неверная почта или пароль." },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(new
    {
        message = "Вход выполнен!",
        username = user.Username
    });
});

app.Run();

public record RegisterRequest(
    string? Username,
    string? Email,
    string? Password);

public record LoginRequest(
    string? Email,
    string? Password);
