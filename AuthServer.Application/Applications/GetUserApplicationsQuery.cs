using MediatR;
using OpenIddict.Abstractions;
using System.Collections.Immutable;

namespace AuthServer.Application.Applications;

public record ApplicationConsentDto(
    string AuthorizationId,
    string ClientId,
    string ApplicationName,
    List<string> Scopes,
    DateTime CreationDate);

public record GetUserApplicationsQuery(Guid UserId) : IRequest<List<ApplicationConsentDto>>;

public class GetUserApplicationsQueryHandler : IRequestHandler<GetUserApplicationsQuery, List<ApplicationConsentDto>>
{
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;

    public GetUserApplicationsQueryHandler(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager)
    {
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
    }

    public async Task<List<ApplicationConsentDto>> Handle(GetUserApplicationsQuery request, CancellationToken cancellationToken)
    {
        var result = new List<ApplicationConsentDto>();

        // Находим все действующие согласия (авторизации) для данного пользователя
        var authorizations = _authorizationManager.FindAsync(
            subject: request.UserId.ToString(),
            client: null, // null означает "любой клиент"
            status: OpenIddictConstants.Statuses.Valid,
            type: OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes: ImmutableArray<string>.Empty,
            cancellationToken: cancellationToken);

        await foreach (var authorization in authorizations)
        {
            var appId = await _authorizationManager.GetApplicationIdAsync(authorization, cancellationToken);
            if (appId == null) continue;

            var application = await _applicationManager.FindByIdAsync(appId, cancellationToken);
            if (application == null) continue;

            var clientId = await _applicationManager.GetClientIdAsync(application, cancellationToken);
            var appName = await _applicationManager.GetLocalizedDisplayNameAsync(application, cancellationToken) ?? clientId;
            var authId = await _authorizationManager.GetIdAsync(authorization, cancellationToken);
            var scopes = await _authorizationManager.GetScopesAsync(authorization, cancellationToken);
            var creationDate = await _authorizationManager.GetCreationDateAsync(authorization, cancellationToken);

            result.Add(new ApplicationConsentDto(
                authId!,
                clientId!,
                appName!,
                scopes.ToList(),
                creationDate?.UtcDateTime ?? DateTime.UtcNow
            ));
        }

        return result;
    }
}
