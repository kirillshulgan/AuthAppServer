namespace AuthServer.Domain.Entities;

public class UserPasskey
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required string CredentialId { get; set; } // Base64 или Hex
    public required string PublicKey { get; set; }
    public string? FriendlyName { get; set; } // Имя устройства
    public uint SignCount { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAt { get; set; }

    public virtual ApplicationUser? User { get; set; }
}
