using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

namespace AuthServer.Host.Controllers;

[ApiExplorerSettings(IgnoreApi = true)] // Скрываем протокольные эндпоинты из Swagger
public class AuthorizationController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AuthorizationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
    }

    [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        // Извлекаем OIDC запрос
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("Запрос не является допустимым OIDC-запросом.");

        // Проверяем, авторизован ли пользователь в системе (Identity cookie)
        var authenticateResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!authenticateResult.Succeeded)
        {
            // Если не авторизован - перенаправляем на страницу логина
            return Challenge(
                properties: new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + Request.QueryString },
                [IdentityConstants.ApplicationScheme]);
        }

        var user = await _userManager.GetUserAsync(authenticateResult.Principal);
        if (user == null)
        {
            return Challenge(
                properties: new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + Request.QueryString },
                [IdentityConstants.ApplicationScheme]);
        }

        // Получаем информацию о клиенте (приложении)
        var client = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Клиентское приложение не найдено.");

        // Разрешаем запрошенные скоупы
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        principal.SetScopes(request.GetScopes());

        // ==========================================
        // ЛОГИКА CONSENT (Согласия)
        // ==========================================
        var consentType = await _applicationManager.GetConsentTypeAsync(client);
        if (consentType != OpenIddictConstants.ConsentTypes.Implicit)
        {
            // Ищем уже выданные ранее согласия (authorizations)
            var authorizations = await _authorizationManager.FindAsync(
                subject: user.Id.ToString(),
                client: (await _applicationManager.GetIdAsync(client))!,
                status: OpenIddictConstants.Statuses.Valid,
                type: OpenIddictConstants.AuthorizationTypes.Permanent,
                scopes: principal.GetScopes()).ToListAsync();

            // Если согласия нет или клиент требует явного подтверждения каждый раз (Explicit)
            if (!authorizations.Any() && consentType == OpenIddictConstants.ConsentTypes.Explicit)
            {
                // Перенаправляем на нашу Razor Page страницу Consent
                return RedirectToPage("/Consent", new
                {
                    returnUrl = Request.PathBase + Request.Path + Request.QueryString
                });
            }

            // Если согласие найдено, привязываем его к токену
            var authorization = authorizations.LastOrDefault();
            if (authorization != null)
            {
                principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            }
        }

        // Настраиваем claims: что пойдет в Access Token, а что в ID Token (согласно ТЗ)
        SetDestinations(principal);

        // Возвращаем SignIn, но указываем схему OpenIddict (он сгенерирует OIDC токены)
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("Запрос не является допустимым OIDC-запросом.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Аутентифицируем на основе переданного authorization_code или refresh_token
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var user = await _userManager.FindByIdAsync(result.Principal.GetClaim(OpenIddictConstants.Claims.Subject)!);
            if (user == null || user.IsDeleted) // Проверка Soft Delete из ТЗ
            {
                return Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetDestinations(result.Principal.GetDestinations());

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("Указанный grant_type не поддерживается.");
    }

    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var subject = User.GetClaim(OpenIddictConstants.Claims.Subject);
        if (subject == null) return Challenge(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

        var user = await _userManager.FindByIdAsync(subject);
        if (user == null || user.IsDeleted) return Challenge(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Subject] = user.Id.ToString()
        };

        if (User.HasScope(OpenIddictConstants.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = user.Email!;
            claims[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            claims[OpenIddictConstants.Claims.GivenName] = user.FirstName ?? string.Empty;
            claims[OpenIddictConstants.Claims.FamilyName] = user.LastName ?? string.Empty;
            // Дополнительные профильные поля по ТЗ
            if (!string.IsNullOrEmpty(user.AvatarUrl))
                claims[OpenIddictConstants.Claims.Picture] = user.AvatarUrl;
        }

        return Ok(claims);
    }

    [HttpGet("~/connect/logout"), HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        // 1. Выход из локальной сессии ASP.NET Core Identity (удаляем куку)
        await _signInManager.SignOutAsync();

        // 2. Указываем OpenIddict, что нужно завершить OIDC сессию
        // Если передан post_logout_redirect_uri, OpenIddict сам перенаправит пользователя
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/" // Если это локальный логаут с сайта, возвращаем на главную
            });
    }

    // Вспомогательный метод для распределения claims по токенам (согласно ТЗ минимизируем Access Token)
    private void SetDestinations(ClaimsPrincipal principal)
    {
        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }
    }

    private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Access Token должен быть минимальным: отправляем туда только Subject (Id) и Role
        // Все остальные профильные данные клиенты заберут через UserInfo Endpoint
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Name or
            OpenIddictConstants.Claims.Email or
            OpenIddictConstants.Claims.GivenName or
            OpenIddictConstants.Claims.FamilyName
                => new[] { OpenIddictConstants.Destinations.IdentityToken },

            OpenIddictConstants.Claims.Role
                => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken },

            _ => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken }
        };
    }
}
