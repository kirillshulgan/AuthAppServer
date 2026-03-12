using MediatR;
using OpenIddict.Abstractions;

namespace AuthServer.Application.Applications;

public record RevokeApplicationConsentCommand(Guid UserId, string AuthorizationId) : IRequest<bool>;

public class RevokeApplicationConsentCommandHandler : IRequestHandler<RevokeApplicationConsentCommand, bool>
{
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictTokenManager _tokenManager;

    public RevokeApplicationConsentCommandHandler(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager)
    {
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
    }

    public async Task<bool> Handle(RevokeApplicationConsentCommand request, CancellationToken cancellationToken)
    {
        // 1. Ищем авторизацию (согласие) по ID
        var authorization = await _authorizationManager.FindByIdAsync(request.AuthorizationId, cancellationToken);
        if (authorization == null) return false;

        // 2. Проверяем, принадлежит ли она этому пользователю
        var subject = await _authorizationManager.GetSubjectAsync(authorization, cancellationToken);
        if (subject != request.UserId.ToString()) return false;

        // 3. Отзываем ВСЕ токены, привязанные к этому согласию (Access, Refresh и т.д.)
        await _tokenManager.RevokeByAuthorizationIdAsync(request.AuthorizationId, cancellationToken);

        // 4. Помечаем саму авторизацию как отозванную (или удаляем)
        await _authorizationManager.DeleteAsync(authorization, cancellationToken);

        return true;
    }
}
