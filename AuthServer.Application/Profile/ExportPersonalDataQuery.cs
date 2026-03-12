using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using System.Text.Json;

namespace AuthServer.Application.Profile;

public record ExportPersonalDataQuery(Guid UserId) : IRequest<byte[]?>;

public class ExportPersonalDataQueryHandler : IRequestHandler<ExportPersonalDataQuery, byte[]?>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ExportPersonalDataQueryHandler(
        UserManager<ApplicationUser> userManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager)
    {
        _userManager = userManager;
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
    }

    public async Task<byte[]?> Handle(ExportPersonalDataQuery request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user == null) return null;

        // 1. Собираем базовые данные (Identity)
        var personalData = new Dictionary<string, object>
        {
            { "UserId", user.Id },
            { "UserName", user.UserName ?? string.Empty },
            { "Email", user.Email ?? string.Empty },
            { "EmailConfirmed", user.EmailConfirmed },
            { "FirstName", user.FirstName ?? string.Empty },
            { "LastName", user.LastName ?? string.Empty },
            { "CreatedAt", user.CreatedAt.ToString("O") },
            { "LastLoginAt", user.LastLoginAt?.ToString("O") ?? "Никогда" }
        };

        // 2. Внешние логины (Social Providers)
        var logins = await _userManager.GetLoginsAsync(user);
        personalData.Add("ExternalLogins", logins.Select(l => new
        {
            Provider = l.LoginProvider,
            ProviderKey = l.ProviderKey
        }));

        // 3. Выданные согласия (Consent)
        var consents = new List<object>();
        var authorizations = _authorizationManager.FindAsync(
            subject: user.Id.ToString(),
            client: null,
            status: OpenIddictConstants.Statuses.Valid,
            type: OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes: System.Collections.Immutable.ImmutableArray<string>.Empty,
            cancellationToken: cancellationToken);

        await foreach (var auth in authorizations)
        {
            var appId = await _authorizationManager.GetApplicationIdAsync(auth, cancellationToken);
            if (appId == null) continue;

            var app = await _applicationManager.FindByIdAsync(appId, cancellationToken);
            var appName = app != null ? await _applicationManager.GetLocalizedDisplayNameAsync(app, cancellationToken) : "Unknown";

            consents.Add(new
            {
                ApplicationName = appName,
                Scopes = await _authorizationManager.GetScopesAsync(auth, cancellationToken),
                GrantedAt = await _authorizationManager.GetCreationDateAsync(auth, cancellationToken)
            });
        }
        personalData.Add("GrantedApplications", consents);

        // Сериализуем всё в красивый JSON
        return JsonSerializer.SerializeToUtf8Bytes(personalData, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }
}
