using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class ForgotPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender, ILogger<ForgotPasswordModel> logger)
    {
        _userManager = userManager;
        _emailSender = emailSender;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат Email")]
        [Display(Name = "Ваш Email")]
        public string Email { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        var user = await _userManager.FindByEmailAsync(Input.Email);

        // Защита от Enumeration Attack: всегда возвращаем успех
        if (user != null && await _userManager.IsEmailConfirmedAsync(user))
        {
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);

            // ВАЖНО: Кодируем токен для безопасной передачи в URL
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var callbackUrl = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { email = Input.Email, code = code },
                protocol: Request.Scheme);

            _logger.LogInformation("ССЫЛКА ДЛЯ СБРОСА ПАРОЛЯ {Email}: {Url}", user.Email, callbackUrl);

            // Отправка реального письма!
            var htmlMessage = $@"
                <div style='font-family: Arial, sans-serif; padding: 20px; text-align: center;'>
                    <h2>Сброс пароля</h2>
                    <p>Для вашего аккаунта был запрошен сброс пароля.</p>
                    <a href='{callbackUrl}' style='display: inline-block; padding: 10px 20px; margin: 20px 0; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;'>Установить новый пароль</a>
                    <p style='color: #6c757d; font-size: 0.9em;'>Если это были не вы, просто проигнорируйте это письмо.</p>
                </div>";

            await _emailSender.SendEmailAsync(Input.Email, "Сброс пароля - Shulgan Auth", htmlMessage);
        }
        else
        {
            _logger.LogWarning("Запрос на сброс для несуществующего или неподтвержденного email: {Email}", Input.Email);
        }

        return RedirectToPage("./ForgotPasswordConfirmation");
    }
}
