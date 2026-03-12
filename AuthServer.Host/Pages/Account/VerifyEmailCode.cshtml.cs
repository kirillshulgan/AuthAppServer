using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class VerifyEmailCodeModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<VerifyEmailCodeModel> _logger;

    public VerifyEmailCodeModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<VerifyEmailCodeModel> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Код обязателен")]
        [StringLength(6, ErrorMessage = "Код должен состоять из 6 цифр", MinimumLength = 6)]
        public string Code { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
    }

    public IActionResult OnGet(string email, string? returnUrl = null)
    {
        if (string.IsNullOrEmpty(email)) return RedirectToPage("./Login");

        Input.Email = email;
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        if (!ModelState.IsValid) return Page();

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user != null && user.IsDeleted)
        {
            ModelState.AddModelError(string.Empty, "Данный аккаунт был удален.");
            return Page();
        }

        // Защита от Enumeration: если пользователь не найден, симулируем неверный код
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Неверный или истекший код.");
            return Page();
        }

        // Проверяем токен, сгенерированный на предыдущем шаге
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            TokenOptions.DefaultEmailProvider,
            Input.Code);

        if (isValid)
        {
            // Осуществляем вход, игнорируя проверку пароля, так как это Passwordless
            await _signInManager.SignInAsync(user, Input.RememberMe);
            _logger.LogInformation("Пользователь {Email} успешно вошел по коду.", user.Email);

            return SafeRedirect(ReturnUrl);
        }

        _logger.LogWarning("Неудачная попытка входа по коду для {Email}.", user.Email);
        ModelState.AddModelError(string.Empty, "Неверный или истекший код.");
        return Page();
    }

    private IActionResult SafeRedirect(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl)) return LocalRedirect(returnUrl);
        return Redirect("~/");
    }
}
