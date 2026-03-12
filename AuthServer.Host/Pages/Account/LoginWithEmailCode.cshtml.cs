using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class LoginWithEmailCodeModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginWithEmailCodeModel> _logger;

    public LoginWithEmailCodeModel(
        UserManager<ApplicationUser> userManager,
        ILogger<LoginWithEmailCodeModel> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат Email")]
        public string Email { get; set; } = string.Empty;
    }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
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

        // ВАЖНО: Защита от Enumeration Attack. 
        // Если пользователь не найден, мы всё равно редиректим на следующую страницу,
        // чтобы злоумышленник не понял, есть такой email в базе или нет (по вашему ТЗ).
        if (user != null)
        {
            // Генерируем 6-значный код для Email
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

            // TODO: Отправить код на email. В реальном проекте тут будет IEmailSender.
            _logger.LogInformation("КОД ДЛЯ ВХОДА ПОЛЬЗОВАТЕЛЯ {Email}: {Code}", user.Email, code);
            // Для целей тестирования мы выводим его в консоль/логи.
        }

        // Перенаправляем на страницу ввода кода, передавая email в параметрах
        return RedirectToPage("./VerifyEmailCode", new { email = Input.Email, returnUrl = ReturnUrl });
    }

}
