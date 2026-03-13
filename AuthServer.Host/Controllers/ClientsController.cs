using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace AuthServer.Host.Controllers;

// [Authorize(Roles = "Admin")] 
public class ClientsController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ClientsController(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    [HttpGet("/clients/register")]
    public async Task<IActionResult> Register(string clientId, string redirectUri, string postLogoutUri = null, string displayName = null)
    {
        // 1. Валидация
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
        {
            return BadRequest("Параметры clientId и redirectUri обязательны.");
        }

        // 2. Проверка на существование
        var existingClient = await _applicationManager.FindByClientIdAsync(clientId);
        if (existingClient != null)
        {
            return Content($"Ошибка: Клиент с ID '{clientId}' уже зарегистрирован в системе.");
        }

        // 3. Генерация надежного секрета
        var clientSecret = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");

        // 4. Настройка прав (Permissions) для клиента
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? clientId : displayName,

            // ИСправлено: Type -> ClientType
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

            RedirectUris = { new Uri(redirectUri) },

            Permissions =
                {
                    // Разрешаем потоки
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                    // Разрешаем эндпоинты
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.Endpoints.Revocation,

                    // Разрешаем запрашивать scopes
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                },
            Requirements =
                {
                    // Принудительно требуем PKCE
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
        };

        // Если передали URL для редиректа после логаута - добавляем
        if (!string.IsNullOrWhiteSpace(postLogoutUri))
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutUri));
        }

        // 5. Сохранение в БД
        await _applicationManager.CreateAsync(descriptor);

        // 6. Передача данных в представление
        ViewBag.ClientId = clientId;
        ViewBag.ClientSecret = clientSecret;
        ViewBag.RedirectUri = redirectUri;
        ViewBag.DisplayName = descriptor.DisplayName;

        return View("ClientCreated");
    }
}
