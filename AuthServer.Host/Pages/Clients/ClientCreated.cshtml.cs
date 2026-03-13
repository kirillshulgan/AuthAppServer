using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace AuthServer.Host.Pages.Clients;

// [Authorize(Roles = "Admin")]
public class ClientCreatedModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ClientCreatedModel(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string RedirectUri { get; set; }
    public string DisplayName { get; set; }

    public string ErrorMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(string clientId, string redirectUri, string postLogoutUri = null, string displayName = null)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
        {
            ErrorMessage = "Параметры clientId и redirectUri обязательны.";
            return Page();
        }

        var existingClient = await _applicationManager.FindByClientIdAsync(clientId);
        if (existingClient != null)
        {
            ErrorMessage = $"Ошибка: Клиент с ID '{clientId}' уже зарегистрирован в системе.";
            return Page();
        }

        ClientSecret = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        ClientId = clientId;
        RedirectUri = redirectUri;
        DisplayName = string.IsNullOrWhiteSpace(displayName) ? clientId : displayName;

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            DisplayName = DisplayName,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            RedirectUris = { new Uri(RedirectUri) },
            Permissions =
            {
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };

        if (!string.IsNullOrWhiteSpace(postLogoutUri))
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutUri));
        }

        await _applicationManager.CreateAsync(descriptor);

        return Page();
    }
}
