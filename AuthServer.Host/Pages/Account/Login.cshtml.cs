using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager,ILogger<LoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IList<AuthenticationScheme> ExternalLogins { get; set; } = new List<AuthenticationScheme>();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Пароль обязателен")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Запомнить меня")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            ModelState.AddModelError(string.Empty, ErrorMessage);
        }

        // Очищаем существующую сессию Identity, чтобы гарантировать чистый вход
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // Получаем список настроенных внешних провайдеров (Google, GitHub, и т.д.)
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (!ModelState.IsValid) return Page();

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user != null && user.IsDeleted)
        {
            ModelState.AddModelError(string.Empty, "Данный аккаунт был удален.");
            return Page();
        }

        // Важно: lockoutOnFailure: true защищает от перебора паролей (требование из ТЗ)
        var result = await _signInManager.PasswordSignInAsync(
            Input.Email,
            Input.Password,
            Input.RememberMe,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            _logger.LogInformation("Пользователь {Email} успешно вошел в систему.", Input.Email);
            return SafeRedirect(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            // Задел на будущее (Этап 2 из ТЗ)
            return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("Аккаунт пользователя {Email} временно заблокирован.", Input.Email);
            return RedirectToPage("./Lockout");
        }

        // В ТЗ указано: "Отображение ошибок без раскрытия лишней информации о существовании аккаунта"
        ModelState.AddModelError(string.Empty, "Неверный логин или пароль.");
        return Page();
    }

    // Обработчик для кнопок Social Login
    public IActionResult OnPostExternalLogin(string provider, string? returnUrl = null)
    {
        // Запрашиваем редирект к внешнему провайдеру (Google/GitHub)
        var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

        return new ChallengeResult(provider, properties);
    }

    private IActionResult SafeRedirect(string returnUrl)
    {
        // Защита от Open Redirect уязвимостей (Требование из ТЗ)
        // Для OIDC returnUrl обычно выглядит как "/connect/authorize?client_id=..."
        if (Url.IsLocalUrl(returnUrl))
        {
            return LocalRedirect(returnUrl);
        }
        return Redirect("~/");
    }
}
