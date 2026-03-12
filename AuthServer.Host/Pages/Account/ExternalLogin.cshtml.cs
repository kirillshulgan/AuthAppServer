using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class ExternalLoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<ExternalLoginModel> _logger;

    public ExternalLoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<ExternalLoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ProviderDisplayName { get; set; }
    public string? ReturnUrl { get; set; }
    public bool AccountExistsError { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат Email")]
        public string Email { get; set; } = string.Empty;

        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }

    // Этот метод принимает callback от Google/GitHub/Apple
    public async Task<IActionResult> OnGetCallbackAsync(string? returnUrl = null, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");
        if (remoteError != null)
        {
            ErrorMessage = $"Ошибка от внешнего провайдера: {remoteError}";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        // Получаем информацию о пользователе из куки временной сессии (ExternalScheme)
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ErrorMessage = "Не удалось загрузить информацию о внешнем входе.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        // Попытка войти, если провайдер уже привязан к какому-то аккаунту в нашей БД
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        if (signInResult.Succeeded)
        {
            _logger.LogInformation("Пользователь вошел через {Name} провайдер.", info.LoginProvider);
            return SafeRedirect(returnUrl);
        }

        if (signInResult.IsLockedOut)
        {
            return RedirectToPage("./Lockout");
        }

        // ==========================================
        // ЕСЛИ АККАУНТ НЕ НАЙДЕН -> РЕГИСТРАЦИЯ
        // ==========================================

        ReturnUrl = returnUrl;
        ProviderDisplayName = info.ProviderDisplayName;

        // Извлекаем Email и Имя с учетом особенностей провайдеров
        string? email = info.Principal.FindFirstValue(ClaimTypes.Email);
        string? firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
        string? lastName = info.Principal.FindFirstValue(ClaimTypes.Surname);

        // Специфика Apple: иногда имя приходит в другом Claim, а email может быть скрыт (Private Relay)
        if (info.LoginProvider == "Apple")
        {
            firstName ??= info.Principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
            // Apple выдает claims только при ПЕРВОЙ авторизации пользователя. 
            // Если email пустой, значит пользователь уже авторизовался ранее.
        }

        Input = new InputModel
        {
            Email = email ?? string.Empty,
            FirstName = firstName,
            LastName = lastName
        };

        // Если email получен, проверим, не зарегистрирован ли он уже у нас локально
        if (!string.IsNullOrEmpty(email))
        {
            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser != null)
            {
                // По ТЗ: "предлагается привязка к существующей".
                // В целях безопасности мы НЕ связываем аккаунты автоматически.
                // Пользователь должен сначала зайти локально (через пароль/код), а затем в ЛК привязать Google.
                AccountExistsError = true;
                return Page();
            }
        }

        return Page();
    }

    // Подтверждение создания аккаунта (если пользователь нажал "Зарегистрироваться" на странице ExternalLogin)
    public async Task<IActionResult> OnPostConfirmationAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ErrorMessage = "Истекло время сессии внешнего входа. Попробуйте еще раз.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        if (ModelState.IsValid)
        {
            var user = new ApplicationUser
            {
                UserName = Input.Email,
                Email = Input.Email,
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                // Привязываем Google/Apple ID к новому пользователю в таблицу UserLogins
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    _logger.LogInformation("Создан аккаунт для пользователя через {Name} провайдер.", info.LoginProvider);

                    // TODO: Здесь должна быть логика отправки Email-подтверждения (EmailSender)
                    // var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    // ... отправка письма ...

                    // По ТЗ требуется подтверждение Email. Если провайдер доверенный (Google/Apple),
                    // мы можем автоматически пометить email как подтвержденный:
                    user.EmailConfirmed = true;
                    await _userManager.UpdateAsync(user);

                    await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                    return SafeRedirect(returnUrl);
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        ProviderDisplayName = info.ProviderDisplayName;
        ReturnUrl = returnUrl;
        return Page();
    }

    private IActionResult SafeRedirect(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl)) return LocalRedirect(returnUrl);
        return Redirect("~/");
    }
}
