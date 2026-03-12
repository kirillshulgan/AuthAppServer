using AuthServer.Application.Applications;
using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace AuthServer.Host.Pages.Profile;

[Authorize]
public class ApplicationsModel : PageModel
{
    private readonly ISender _sender;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<ApplicationsModel> _logger;

    public ApplicationsModel(ISender sender, UserManager<ApplicationUser> userManager , ILogger<ApplicationsModel> logger)
    {
        _sender = sender;
        _userManager = userManager;
        _logger = logger;
    }

    public List<ApplicationConsentDto> Consents { get; set; } = new();

    [TempData]
    public string? StatusMessage { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var userId = Guid.Parse(_userManager.GetUserId(User)!);
        Consents = await _sender.Send(new GetUserApplicationsQuery(userId));
        return Page();
    }

    public async Task<IActionResult> OnPostRevokeAsync(string authorizationId)
    {
        if (string.IsNullOrEmpty(authorizationId)) return BadRequest();

        var userId = Guid.Parse(_userManager.GetUserId(User)!);

        var success = await _sender.Send(new RevokeApplicationConsentCommand(userId, authorizationId));

        if (success)
        {
            _logger.LogInformation("Пользователь {UserId} отозвал доступ для AuthorizationId: {AuthId}", userId, authorizationId);
            StatusMessage = "Доступ приложению успешно отозван. Все активные сессии завершены.";
        }
        else
        {
            StatusMessage = "Ошибка: не удалось отозвать доступ. Возможно, он уже был отозван.";
        }

        return RedirectToPage();
    }
}
