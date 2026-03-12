namespace AuthServer.Domain.Entities;

public class EmailLoginCode
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required string Email { get; set; }
    public required string CodeHash { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }

    public virtual ApplicationUser? User { get; set; }
}
