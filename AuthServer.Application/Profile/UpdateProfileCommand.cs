using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Application.Profile;

// Команда. Возвращает bool (успешно/неуспешно)
public record UpdateProfileCommand(Guid UserId, string? FirstName, string? LastName) : IRequest<bool>;

// Обработчик команды
public class UpdateProfileCommandHandler : IRequestHandler<UpdateProfileCommand, bool>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UpdateProfileCommandHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<bool> Handle(UpdateProfileCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user == null) return false;

        user.FirstName = request.FirstName;
        user.LastName = request.LastName;

        var result = await _userManager.UpdateAsync(user);
        return result.Succeeded;
    }
}
