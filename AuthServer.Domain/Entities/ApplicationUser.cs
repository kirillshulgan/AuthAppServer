using Microsoft.AspNetCore.Identity;

namespace AuthServer.Domain.Entities;

// Кастомный пользователь
public class ApplicationUser : IdentityUser<Guid>
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? AvatarUrl { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    // Soft Delete (по ТЗ: grace period)
    public bool IsDeleted { get; set; }
    public DateTime? DeletionRequestedAt { get; set; }

    // Навигационные свойства для кастомных сущностей
    public virtual ICollection<EmailLoginCode> EmailLoginCodes { get; set; } = new List<EmailLoginCode>();
}

// Кастомная роль
public class ApplicationRole : IdentityRole<Guid>
{
    public string? Description { get; set; }
}
