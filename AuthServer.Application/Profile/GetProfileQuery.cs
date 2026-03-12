using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Application.Profile;

// DTO, которое возвращается на UI
public record ProfileDto(string Email, string? FirstName, string? LastName, string? AvatarUrl, bool IsEmailConfirmed);

// Запрос. Принимает UserId
public record GetProfileQuery(Guid UserId) : IRequest<ProfileDto?>;

// Обработчик запроса
public class GetProfileQueryHandler : IRequestHandler<GetProfileQuery, ProfileDto?>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public GetProfileQueryHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<ProfileDto?> Handle(GetProfileQuery request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user == null) return null;

        return new ProfileDto(
            user.Email!,
            user.FirstName,
            user.LastName,
            user.AvatarUrl,
            user.EmailConfirmed
        );
    }
}
