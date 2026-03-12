using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Application.Profile;

public record ChangePasswordCommand(Guid UserId, string CurrentPassword, string NewPassword) : IRequest<IdentityResult>;

public class ChangePasswordCommandHandler : IRequestHandler<ChangePasswordCommand, IdentityResult>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ChangePasswordCommandHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IdentityResult> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user == null) return IdentityResult.Failed(new IdentityError { Description = "Пользователь не найден." });

        // Метод ChangePasswordAsync сам проверяет старый пароль и устанавливает новый (Re-authentication)
        return await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
    }
}
