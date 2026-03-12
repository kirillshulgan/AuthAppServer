using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class ForgotPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(UserManager<ApplicationUser> userManager, ILogger<ForgotPasswordModel> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат Email")]
        public string Email { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        var user = await _userManager.FindByEmailAsync(Input.Email);

        // Защита от Enumeration Attack из ТЗ: 
        // Мы всегда возвращаем успешный ответ, даже если email не найден
        if (user != null && await _userManager.IsEmailConfirmedAsync(user))
        {
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);

            // В реальном проекте тут будет IEmailSender
            // Ссылка должна вести на страницу ResetPassword, передавая email и code
            var callbackUrl = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { email = Input.Email, code = code },
                protocol: Request.Scheme);

            _logger.LogInformation("ССЫЛКА ДЛЯ СБРОСА ПАРОЛЯ {Email}: {Url}", user.Email, callbackUrl);
        }
        else
        {
            _logger.LogWarning("Запрос на сброс для несуществующего или неподтвержденного email: {Email}", Input.Email);
        }

        return RedirectToPage("./ForgotPasswordConfirmation");
    }
}
