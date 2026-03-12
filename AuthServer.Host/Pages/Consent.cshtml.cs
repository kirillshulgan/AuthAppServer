using AuthServer.Domain.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthServer.Host.Pages;

[Authorize] // На эту страницу может попасть только залогиненный пользователь
public class ConsentModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public ConsentModel(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string ApplicationName { get; set; } = string.Empty;
    public List<ScopeViewModel> Scopes { get; set; } = new();

    public class ScopeViewModel
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return BadRequest("ReturnUrl is missing.");
        }

        ReturnUrl = returnUrl;

        // В returnUrl у нас лежит строка вида "/connect/authorize?client_id=..."
        // Мы можем распарсить её, чтобы достать client_id и scope

        // 1. Создаем фальшивый HttpContext на основе returnUrl, чтобы OpenIddict мог его прочитать
        // Но так как это сложно, мы просто распарсим QueryString

        var uri = new Uri(Request.Scheme + "://" + Request.Host + returnUrl);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        var clientId = query["client_id"].ToString();
        var scopeString = query["scope"].ToString();

        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest("Не найден client_id в запросе.");
        }

        // Получаем информацию о клиенте
        var application = await _applicationManager.FindByClientIdAsync(clientId) ??
            throw new InvalidOperationException("Клиентское приложение не найдено.");

        ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application) ?? clientId;

        // Получаем список запрашиваемых скоупов
        var scopes = scopeString.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var scope in scopes)
        {
            var scopeEntity = await _scopeManager.FindByNameAsync(scope);
            if (scopeEntity != null)
            {
                Scopes.Add(new ScopeViewModel
                {
                    Name = scope,
                    DisplayName = (await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntity)) ?? scope,
                    Description = (await _scopeManager.GetLocalizedDescriptionAsync(scopeEntity)) ?? "Доступ к данным"
                });
            }
            else
            {
                Scopes.Add(new ScopeViewModel
                {
                    Name = scope,
                    DisplayName = scope,
                    Description = GetDefaultScopeDescription(scope)
                });
            }
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string accept, string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return BadRequest();

        // Если пользователь отказал - мы редиректим его обратно в OIDC, 
        // но добавляем параметр ошибки (OpenIddict поймет его)
        if (!string.Equals(accept, "true", StringComparison.OrdinalIgnoreCase))
        {
            // Вместо Forbid() возвращаем пользователя в OIDC флоу с ошибкой
            var separator = returnUrl.Contains('?') ? "&" : "?";
            return Redirect(returnUrl + separator + "error=access_denied&error_description=User_denied_consent");
        }

        // Если разрешил - парсим client_id и scopes из returnUrl
        var uri = new Uri(Request.Scheme + "://" + Request.Host + returnUrl);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        var clientId = query["client_id"].ToString();
        var scopes = query["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var user = await _userManager.GetUserAsync(User) ?? throw new InvalidOperationException();
        var application = await _applicationManager.FindByClientIdAsync(clientId) ?? throw new InvalidOperationException();
        var applicationId = await _applicationManager.GetIdAsync(application);

        // Сохраняем согласие в базу
        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            Subject = user.Id.ToString(),
            ApplicationId = applicationId,
            Status = OpenIddictConstants.Statuses.Valid,
            Type = OpenIddictConstants.AuthorizationTypes.Permanent
        };
        descriptor.Scopes.UnionWith(scopes);

        await _authorizationManager.CreateAsync(descriptor);

        // Возвращаем пользователя обратно на эндпоинт /connect/authorize
        // Там контроллер найдет только что созданное согласие и сгенерирует токены!
        return Redirect(returnUrl);
    }

    private IEnumerable<string> GetDestinations(System.Security.Claims.Claim claim)
    {
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email => new[] { OpenIddictConstants.Destinations.IdentityToken },
            OpenIddictConstants.Claims.Role => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken },
            _ => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken }
        };
    }

    private static string GetDefaultScopeDescription(string scope)
    {
        return scope switch
        {
            OpenIddictConstants.Scopes.OpenId => "Базовая авторизация",
            OpenIddictConstants.Scopes.Email => "Доступ к вашему email-адресу",
            OpenIddictConstants.Scopes.Profile => "Доступ к вашему профилю (имя, аватар)",
            OpenIddictConstants.Scopes.OfflineAccess => "Поддержание сессии в фоновом режиме",
            OpenIddictConstants.Scopes.Roles => "Чтение ваших ролей",
            _ => "Доступ к данным приложения"
        };
    }
}
