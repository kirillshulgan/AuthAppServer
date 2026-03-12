using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthServer.Host.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [StringLength(100, ErrorMessage = "{0} должен быть от {2} до {1} символов.", MinimumLength = 10)]
            [DataType(DataType.Password)]
            [Display(Name = "Новый пароль")]
            public string Password { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [Display(Name = "Подтвердите пароль")]
            [Compare("Password", ErrorMessage = "Пароли не совпадают.")]
            public string ConfirmPassword { get; set; } = string.Empty;

            [Required]
            public string Code { get; set; } = string.Empty;
        }

        public IActionResult OnGet(string? code = null, string? email = null)
        {
            if (code == null || email == null)
            {
                return BadRequest("Для сброса пароля необходимо указать код и email.");
            }

            Input = new InputModel
            {
                Code = code,
                Email = email
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // У вас в коде был редирект сюда, нужно будет создать эту страницу, если её нет. Либо отправлять на ./Login
                return RedirectToPage("./ResetPasswordConfirmation"); 
            }

            // ВАЖНО: Декодируем токен из URL формата обратно в строку
            var decodedCode = string.Empty;
            try
            {
                var decodedBytes = WebEncoders.Base64UrlDecode(Input.Code);
                decodedCode = Encoding.UTF8.GetString(decodedBytes);
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Неверный формат кода восстановления.");
                return Page();
            }

            // Сбрасываем пароль
            var result = await _userManager.ResetPasswordAsync(user, decodedCode, Input.Password);
            if (result.Succeeded)
            {
                // Рекомендуется перекидывать на страницу подтверждения
                return RedirectToPage("./Login", new { message = "Пароль успешно изменен! Теперь вы можете войти." });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}
