using AuthServer.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace AuthServer.Migrator;

public class DbMigratorHostedService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<DbMigratorHostedService> _logger;
    private readonly IHostApplicationLifetime _lifetime;

    public DbMigratorHostedService(
        IServiceProvider serviceProvider,
        ILogger<DbMigratorHostedService> logger,
        IHostApplicationLifetime lifetime)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _lifetime = lifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Запуск миграции базы данных и создания базовых сущностей...");

        using var scope = _serviceProvider.CreateScope();

        // 1. Применяем миграции
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await context.Database.MigrateAsync(cancellationToken);
        _logger.LogInformation("Миграции успешно применены.");

        // 2. Сидируем Scopes (Описания для Consent экрана)
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        await SeedScopesAsync(scopeManager, cancellationToken);

        // 3. Сидируем Клиентов (WPF приложение)
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedApplicationsAsync(appManager, cancellationToken);

        _logger.LogInformation("Инициализация базы данных завершена. Остановка мигратора.");
        _lifetime.StopApplication(); // Автоматически завершаем консольное приложение
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SeedScopesAsync(IOpenIddictScopeManager manager, CancellationToken cancellationToken)
    {
        // Создаем кастомный скоуп "roles", если его нет
        if (await manager.FindByNameAsync("roles", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "roles",
                DisplayName = "Доступ к ролям",
                Description = "Позволяет приложению видеть ваши роли и уровень доступа."
            }, cancellationToken);
            _logger.LogInformation("Скоуп 'roles' создан.");
        }

        if (await manager.FindByNameAsync("profile", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "profile",
                DisplayName = "Профиль пользователя",
                Description = "Доступ к имени, фамилии и аватару."
            }, cancellationToken);
            _logger.LogInformation("Скоуп 'profile' создан.");
        }
    }

    private async Task SeedApplicationsAsync(IOpenIddictApplicationManager manager, CancellationToken cancellationToken)
    {
        const string wpfClientId = "wpf_desktop_client";

        if (await manager.FindByClientIdAsync(wpfClientId, cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = wpfClientId,
                DisplayName = "WPF MyCompany Desktop App",

                // ВАЖНО: Для WPF типа ConsentType.Explicit заставит пользователя 
                // один раз подтвердить доступ к профилю (Consent Screen)
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

                // Для WPF/Mobile используется Public клиент (без ClientSecret)
                ClientType = OpenIddictConstants.ClientTypes.Public,

                // Разрешаем Authorization Code Flow + PKCE и Refresh Token
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    
                    // Разрешаем возвращать код авторизации
                    OpenIddictConstants.Permissions.ResponseTypes.Code, 

                    // Указываем скоупы, которые может запрашивать клиент
                    OpenIddictConstants.Permissions.Prefixes.Scope + "profile",
                    OpenIddictConstants.Permissions.Prefixes.Scope + "roles"
                },

                // Требуем PKCE для безопасности
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                },

                // Урлы, на которые OIDC-серверу разрешено перенаправлять после логина
                // В WPF обычно поднимают локальный HttpListener, например на порту 50000
                RedirectUris =
                {
                    new Uri("http://127.0.0.1:50000/callback"),
                    new Uri("myapp://callback") // Схема для системного браузера (если используется Deep Linking)
                },

                PostLogoutRedirectUris =
                {
                    new Uri("http://127.0.0.1:50000/logout-callback"),
                    new Uri("myapp://logout-callback")
                }
            }, cancellationToken);

            _logger.LogInformation("Клиент 'WPF Desktop App' успешно зарегистрирован.");
        }
    }
}
