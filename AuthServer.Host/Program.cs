using AuthServer.Domain.Entities;
using AuthServer.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Quartz;
using StackExchange.Redis;

if (File.Exists(".env"))
{
    DotNetEnv.Env.Load();
}

var builder = WebApplication.CreateBuilder(args);

// ==========================================
// 1. НАСТРОЙКА БАЗЫ ДАННЫХ И КЭША
// ==========================================

builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict<Guid>();
});

// Настраиваем Redis с защитой от падения при старте
var redisConnectionString = builder.Configuration.GetConnectionString("Redis");
IConnectionMultiplexer? redis = null;

try
{
    if (!string.IsNullOrEmpty(redisConnectionString))
    {
        // Пытаемся подключиться к Redis
        redis = ConnectionMultiplexer.Connect(redisConnectionString);
        builder.Services.AddSingleton<IConnectionMultiplexer>(redis);
    }
}
catch (Exception ex)
{
    // Логируем ошибку, но НЕ роняем приложение в Development-режиме
    Console.WriteLine($"[WARNING] Не удалось подключиться к Redis: {ex.Message}. Используется локальный фоллбэк.");
}

// Настройка Data Protection
var dataProtectionBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("AuthServer");

if (redis != null)
{
    // Если Redis работает - храним ключи там (для продакшена/Docker)
    dataProtectionBuilder.PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys");
}
else
{
    // Если Redis недоступен - храним ключи в папке проекта (для локальной разработки)
    var keysFolder = Path.Combine(builder.Environment.ContentRootPath, "App_Data", "Keys");
    dataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo(keysFolder));
}

// ==========================================
// 2. НАСТРОЙКА ASP.NET CORE IDENTITY
// ==========================================

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    // Политика паролей (из ТЗ)
    options.Password.RequiredLength = 10;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;

    // Подтверждение аккаунта
    options.SignIn.RequireConfirmedEmail = true;

    // Блокировка аккаунта (на будущее)
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    // НАСТРОЙКА МАППИНГА CLAIMS ДЛЯ OPENIDDICT
    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject; // ВОТ ЭТО САМОЕ ГЛАВНОЕ
    options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
    options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;

    // НАСТРОЙКА ВЕРСИИ ДЛЯ .NET 10 PASSKEYS:
    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders(); // Токены для сброса пароля и email

builder.Services.AddScoped<Microsoft.AspNetCore.Identity.IUserPasskeyStore<ApplicationUser>,
    Microsoft.AspNetCore.Identity.EntityFrameworkCore.UserStore<ApplicationUser, ApplicationRole, AuthDbContext, Guid>>();

// ==========================================
// 3. НАСТРОЙКА OPENIDDICT
// ==========================================

// Добавляем фоновые задачи Quartz (для очистки протухших токенов из БД)
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
});
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddOpenIddict()
    // 3.1. Настройка интеграции с EF Core
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<AuthDbContext>()
               .ReplaceDefaultEntities<Guid>(); // Используем Guid для ключей
    })
    // 3.2. Настройка сервера авторизации (Identity Provider)
    .AddServer(options =>
    {
        // Включаем эндпоинты протокола OIDC
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetEndSessionEndpointUris("connect/logout")
               .SetRevocationEndpointUris("connect/revoke");

        // Разрешаем Authorization Code Flow (для SPA/WPF) и Refresh Token
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow();

        // Обязательное использование PKCE (по ТЗ)
        options.RequireProofKeyForCodeExchange();

        // Регистрируем поддерживаемые scopes
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.OfflineAccess,
            OpenIddictConstants.Scopes.Roles);

        // Настройка интеграции с ASP.NET Core
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableStatusCodePagesIntegration();

        // Ключи шифрования и подписи
        // ВАЖНО: В продакшене использовать .AddEncryptionCertificate() и .AddSigningCertificate()
        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
            options.DisableAccessTokenEncryption(); // Удобно для дебага токенов в jwt.io
        }
        else
        {
            options.AddEphemeralEncryptionKey()
                .AddEphemeralSigningKey();
        }

        // РАЗРЕШАЕМ HTTP
        options.UseAspNetCore().DisableTransportSecurityRequirement();
    })
    // 3.3. Настройка валидации токенов (для UserInfo и локальных API сервиса)
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// ==========================================
// 4. ВНЕШНИЕ ПРОВАЙДЕРЫ (Social Login)
// ==========================================

builder.Services.AddAuthentication(options =>
{
    // По умолчанию используем куки Identity
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
    options.SaveTokens = true; // Нужно для сохранения Refresh/Access токенов провайдера, если понадобятся
})
.AddGitHub(options =>
{
    options.ClientId = builder.Configuration["Authentication:GitHub:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:GitHub:ClientSecret"]!;
})
.AddOpenIdConnect("Telegram", "Telegram", options =>
{
    options.Authority = "https://oauth.telegram.org"; // Discovery документ Telegram
    options.ClientId = builder.Configuration["Authentication:Telegram:ClientId"] ?? "8720807101";
    options.ClientSecret = builder.Configuration["Authentication:Telegram:ClientSecret"] ?? "P5QrTy_RhYAHo4iGU_gusvBre2wwzdEibsIo6Cf7V4RS_44gPHYDTA";

    options.ResponseType = "code";
    options.UsePkce = true;

    // Telegram требует этот callback url. ASP.NET по умолчанию делает /signin-oidc, 
    // но мы назовем его /signin-telegram
    options.CallbackPath = "/signin-telegram";

    // Scope. 'openid' обязателен. Добавляем profile для получения имени и юзернейма
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");

    // Telegram возвращает все данные прямо в ID Token, отдельного UserInfo эндпоинта нет!
    options.GetClaimsFromUserInfoEndpoint = false;

    options.SaveTokens = true;

    // Маппинг клеймов из ID Token в стандартные клеймы ASP.NET Identity
    // Telegram отдает "name", "preferred_username", "picture"
    options.ClaimActions.MapJsonKey(System.Security.Claims.ClaimTypes.NameIdentifier, "sub");
    options.ClaimActions.MapJsonKey(System.Security.Claims.ClaimTypes.Name, "name");
    options.ClaimActions.MapJsonKey("urn:telegram:username", "preferred_username");
    options.ClaimActions.MapJsonKey("urn:telegram:picture", "picture");
});

// ==========================================
// 5. НАСТРОЙКИ MediatR
// ==========================================

builder.Services.AddMediatR(cfg => 
    cfg.RegisterServicesFromAssembly(
        typeof(AuthServer.Application.Profile.GetProfileQuery).Assembly));

// ==========================================
// 6. НАСТРОЙКИ UI И АРХИТЕКТУРЫ
// ==========================================

builder.Services.AddRazorPages(options =>
{
    // Требуем авторизацию для Личного кабинета
    options.Conventions.AuthorizeFolder("/Profile");

    // Явно разрешаем доступ ко всем страницам в папке Account
    options.Conventions.AllowAnonymousToFolder("/Account");

    // Страница согласия тоже требует авторизации
    options.Conventions.AuthorizePage("/Consent");

    // Перенаправляем корневой URL (/) на страницу профиля
    options.Conventions.AddPageRoute("/Profile/Index", "");
});
builder.Services.AddControllersWithViews(); // Для OIDC контроллеров

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

// ==========================================
// 7. Настройка Pipeline
// ==========================================
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// ==========================================
// 8. PASSKEYS (WebAuthn) ENDPOINTS
// ==========================================

var passkeysGroup = app.MapGroup("/api/passkeys").RequireAuthorization();

// 1. Генерация опций для регистрации нового Passkey
passkeysGroup.MapPost("/register-options", async (
    HttpContext context,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) =>
{
    var user = await userManager.GetUserAsync(context.User);
    if (user is null) return Results.NotFound();

    var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new()
    {
        Id = user.Id.ToString(),
        Name = user.Email ?? user.UserName ?? "User",
        DisplayName = user.FirstName ?? user.Email ?? "User"
    });

    return Results.Text(optionsJson, contentType: "application/json");
});

// 2. Валидация созданного ключа и сохранение в БД
passkeysGroup.MapPost("/register", async (
    HttpContext context,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager) => // Добавьте userManager в параметры
{
    using var reader = new StreamReader(context.Request.Body);
    var credentialJson = await reader.ReadToEndAsync();

    try
    {
        // 1. Проверяем валидность присланного ключа от устройства
        var attestationResult = await signInManager.PerformPasskeyAttestationAsync(credentialJson);

        if (!attestationResult.Succeeded)
        {
            // Берем сообщение из attestationResult.Failure
            var msg = attestationResult.Failure?.Message ?? "Неизвестная ошибка валидации ключа.";
            return Results.BadRequest(new[] { new { description = msg } });
        }

        // 2. Получаем текущего пользователя
        var user = await userManager.GetUserAsync(context.User);
        if (user == null)
        {
            return Results.BadRequest(new[] { new { description = "Пользователь не найден." } });
        }

        // 3. Сохраняем проверенный Passkey в базу данных!
        var addResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);

        if (!addResult.Succeeded)
        {
            var errors = addResult.Errors.Select(e => new { description = e.Description }).ToArray();
            return Results.BadRequest(errors);
        }

        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new[] { new { description = ex.Message } });
    }
});

var passkeysLoginGroup = app.MapGroup("/api/passkeys/login").AllowAnonymous();

// 1. Генерация опций для запроса логина (Assertion Options)
passkeysLoginGroup.MapPost("/options", async (
    HttpContext context,
    SignInManager<ApplicationUser> signInManager) =>
{
    // В .NET 10 метод MakePasskeyRequestOptionsAsync генерирует вызов. 
    // Передаем null, чтобы разрешить вход любому пользователю, чей ключ есть на этом устройстве
    var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(null);
    return Results.Text(optionsJson, contentType: "application/json");
});

// 2. Проверка ответа устройства и создание сессии (Sign In)
passkeysLoginGroup.MapPost("/verify", async (
    HttpContext context,
    SignInManager<ApplicationUser> signInManager) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var credentialJson = await reader.ReadToEndAsync();

    try
    {
        // Убираем параметр isPersistent, передаем только JSON
        var result = await signInManager.PasskeySignInAsync(credentialJson);

        if (result.Succeeded)
        {
            return Results.Ok();
        }

        return Results.BadRequest(new[] { new { description = "Ошибка авторизации по ключу." } });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new[] { new { description = ex.Message } });
    }
});

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.Migrate();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Обязательный порядок для Identity и OpenIddict
app.UseAuthentication();
app.UseAuthorization();

// Маппинг Razor Pages (UI сервера) и API контроллеров
app.MapRazorPages();
app.MapControllers();

app.Run();