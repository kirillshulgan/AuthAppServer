using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace AuthServer.Application.Profile;

public record DeleteAccountCommand(Guid UserId) : IRequest<bool>;

public class DeleteAccountCommandHandler : IRequestHandler<DeleteAccountCommand, bool>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictTokenManager _tokenManager;

    public DeleteAccountCommandHandler(
        UserManager<ApplicationUser> userManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager)
    {
        _userManager = userManager;
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
    }

    public async Task<bool> Handle(DeleteAccountCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user == null || user.IsDeleted) return false;

        // 1. Помечаем аккаунт как удаленный (Soft Delete)
        user.IsDeleted = true;
        user.DeletionRequestedAt = DateTime.UtcNow;

        // Очищаем персональные данные (но оставляем ID для логов и сохранения целостности БД)
        user.FirstName = "[DELETED]";
        user.LastName = "[DELETED]";
        user.NormalizedEmail = null;
        user.NormalizedUserName = null;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded) return false;

        // 2. Отзываем все выданные токены (Access/Refresh токенов)
        var tokens = _tokenManager.FindBySubjectAsync(user.Id.ToString(), cancellationToken);
        await foreach (var token in tokens)
        {
            await _tokenManager.TryRevokeAsync(token, cancellationToken);
        }

        // 3. Отзываем все выданные согласия (Consent)
        var authorizations = _authorizationManager.FindBySubjectAsync(user.Id.ToString(), cancellationToken);
        await foreach (var auth in authorizations)
        {
            await _authorizationManager.DeleteAsync(auth, cancellationToken);
        }

        // В реальном приложении здесь можно отправить доменное событие
        // (например: AccountDeletedEvent), чтобы микросервисы (по RabbitMQ/Kafka)
        // тоже подчистили данные этого пользователя.

        return true;
    }
}
