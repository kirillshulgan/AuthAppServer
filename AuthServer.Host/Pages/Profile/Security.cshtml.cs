using AuthServer.Application.Profile;
using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Host.Pages.Profile
{
    [Authorize]
    public class SecurityModel : PageModel
    {
        private readonly ISender _sender;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<SecurityModel> _logger;

        public SecurityModel(ISender sender, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<SecurityModel> logger)
        {
            _sender = sender;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [TempData]
        public string? StatusMessage { get; set; }

        public void OnGet()
        {
        }

        // Обработчик для кнопки экспорта
        public async Task<IActionResult> OnPostExportDataAsync()
        {
            var userIdString = _userManager.GetUserId(User);
            if (userIdString == null) return Challenge();

            var userId = Guid.Parse(userIdString);

            var fileBytes = await _sender.Send(new ExportPersonalDataQuery(userId));
            if (fileBytes == null)
            {
                StatusMessage = "Ошибка при выгрузке данных.";
                return RedirectToPage();
            }

            _logger.LogInformation("Пользователь {UserId} запросил выгрузку персональных данных.", userId);

            // Возвращаем файл в браузер
            return File(fileBytes, "application/json", "PersonalData.json");
        }

        public async Task<IActionResult> OnPostDeleteAccountAsync()
        {
            var userIdString = _userManager.GetUserId(User);
            if (userIdString == null) return Challenge();

            var userId = Guid.Parse(userIdString);

            var isDeleted = await _sender.Send(new DeleteAccountCommand(userId));

            if (isDeleted)
            {
                _logger.LogWarning("Пользователь {UserId} УДАЛИЛ свой аккаунт.", userId);

                // Выходим из локальной сессии
                await _signInManager.SignOutAsync();

                // Перенаправляем на главную страницу (или на специальную страницу "Аккаунт удален")
                return Redirect("~/");
            }

            StatusMessage = "Не удалось удалить аккаунт. Пожалуйста, обратитесь в поддержку.";
            return RedirectToPage();
        }

        [BindProperty]
        public ChangePasswordModel PasswordInput { get; set; } = new();

        public class ChangePasswordModel
        {
            [Required(ErrorMessage = "Введите текущий пароль")]
            [DataType(DataType.Password)]
            [Display(Name = "Текущий пароль")]
            public string CurrentPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Введите новый пароль")]
            [StringLength(100, ErrorMessage = "{0} должен быть от {2} до {1} символов.", MinimumLength = 10)]
            [DataType(DataType.Password)]
            [Display(Name = "Новый пароль")]
            public string NewPassword { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [Display(Name = "Подтвердите пароль")]
            [Compare("NewPassword", ErrorMessage = "Новые пароли не совпадают.")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnPostChangePasswordAsync()
        {
            if (!ModelState.IsValid) return Page();

            var userId = Guid.Parse(_userManager.GetUserId(User)!);
            var result = await _sender.Send(new ChangePasswordCommand(userId, PasswordInput.CurrentPassword, PasswordInput.NewPassword));

            if (result.Succeeded)
            {
                _logger.LogInformation("Пользователь {UserId} успешно изменил пароль.", userId);

                // Re-authentication: пересоздаем сессию, чтобы куки не протухли
                var user = await _userManager.FindByIdAsync(userId.ToString());
                await _signInManager.RefreshSignInAsync(user!);

                StatusMessage = "Пароль успешно изменен.";
                return RedirectToPage();
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}
