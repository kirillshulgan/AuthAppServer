using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.Host.Pages.Account;

[AllowAnonymous]
public class ResetPasswordConfirmationModel : PageModel
{
    public void OnGet()
    {
        // Просто отображаем страницу
    }
}
