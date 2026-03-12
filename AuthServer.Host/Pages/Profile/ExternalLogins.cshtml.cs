using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.Host.Pages.Profile;

[Authorize]
public class ExternalLoginsModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public ExternalLoginsModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public IList<UserLoginInfo> CurrentLogins { get; set; } = new List<UserLoginInfo>();
    public IList<AuthenticationScheme> OtherLogins { get; set; } = new List<AuthenticationScheme>();
    public bool ShowRemoveButton { get; set; }

    [TempData]
    public string? StatusMessage { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound($"Не удалось загрузить пользователя.");

        CurrentLogins = await _userManager.GetLoginsAsync(user);
        var schemes = await _signInManager.GetExternalAuthenticationSchemesAsync();

        // Фильтруем провайдеров, которые еще НЕ привязаны к аккаунту
        OtherLogins = schemes.Where(auth => CurrentLogins.All(ul => auth.Name != ul.LoginProvider)).ToList();

        // Показываем кнопку "Удалить" только если у пользователя есть пароль или больше одного логина,
        // чтобы он не заблокировал себя, отвязав единственный способ входа
        ShowRemoveButton = user.PasswordHash != null || CurrentLogins.Count > 1;

        return Page();
    }

    // Обработчик для удаления привязки (отвязка Google/GitHub)
    public async Task<IActionResult> OnPostRemoveLoginAsync(string loginProvider, string providerKey)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        var result = await _userManager.RemoveLoginAsync(user, loginProvider, providerKey);
        if (!result.Succeeded)
        {
            StatusMessage = "Произошла ошибка при отвязке аккаунта.";
            return RedirectToPage();
        }

        await _signInManager.RefreshSignInAsync(user);
        StatusMessage = $"Аккаунт {loginProvider} успешно отвязан.";
        return RedirectToPage();
    }

    // Обработчик для начала привязки (отправка запроса в Google/GitHub)
    public async Task<IActionResult> OnPostLinkLoginAsync(string provider)
    {
        // Очищаем существующие внешние куки, чтобы обеспечить чистый процесс входа
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // Запрашиваем редирект к внешнему провайдеру
        var redirectUrl = Url.Page("./ExternalLogins", pageHandler: "LinkLoginCallback");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));

        return new ChallengeResult(provider, properties);
    }

    // Callback, который вызывается после того как Google/GitHub вернул ответ
    public async Task<IActionResult> OnGetLinkLoginCallbackAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        var info = await _signInManager.GetExternalLoginInfoAsync(user.Id.ToString());
        if (info == null)
        {
            throw new InvalidOperationException($"Неожиданная ошибка при загрузке информации о внешнем логине.");
        }

        var result = await _userManager.AddLoginAsync(user, info);
        if (!result.Succeeded)
        {
            StatusMessage = "Этот внешний аккаунт уже привязан к другому пользователю.";
            return RedirectToPage();
        }

        // Обновляем сессионные куки
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        await _signInManager.RefreshSignInAsync(user);

        StatusMessage = $"Аккаунт {info.LoginProvider} успешно привязан.";
        return RedirectToPage();
    }
}
