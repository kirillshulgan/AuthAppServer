using AuthServer.Application.Profile;
using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace AuthServer.Host.Pages.Profile;

[Authorize]
public class IndexModel : PageModel
{
    private readonly ISender _sender; // Интерфейс MediatR для отправки команд
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ISender sender, UserManager<ApplicationUser> userManager, ILogger<IndexModel> logger)
    {
        _sender = sender;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string Email { get; set; } = string.Empty;
    public bool IsEmailConfirmed { get; set; }

    [TempData]
    public string? StatusMessage { get; set; }

    public class InputModel
    {
        [Display(Name = "Имя")]
        public string? FirstName { get; set; }

        [Display(Name = "Фамилия")]
        public string? LastName { get; set; }
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var userIdString = _userManager.GetUserId(User);
        if (userIdString == null) return Challenge();

        var userId = Guid.Parse(userIdString);

        // Запрашиваем данные через MediatR
        var profile = await _sender.Send(new GetProfileQuery(userId));

        if (profile == null) return NotFound($"Не удалось загрузить пользователя с ID '{userId}'.");

        Email = profile.Email;
        IsEmailConfirmed = profile.IsEmailConfirmed;
        Input = new InputModel
        {
            FirstName = profile.FirstName,
            LastName = profile.LastName
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        var userId = Guid.Parse(_userManager.GetUserId(User)!);

        // Отправляем команду обновления через MediatR
        var isSuccess = await _sender.Send(new UpdateProfileCommand(userId, Input.FirstName, Input.LastName));

        if (isSuccess)
        {
            _logger.LogInformation("Пользователь {UserId} обновил профиль.", userId);
            StatusMessage = "Ваш профиль успешно обновлен!";
            return RedirectToPage();
        }

        ModelState.AddModelError(string.Empty, "Произошла ошибка при обновлении профиля.");
        return await OnGetAsync(); // Перезагружаем страницу с ошибкой
    }
}
