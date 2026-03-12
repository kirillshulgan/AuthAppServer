namespace AuthServer.Domain.Entities;

public class PersonalDataExport
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public ExportStatus Status { get; set; }
    public string? FileUrl { get; set; } // Ссылка на S3/MinIO
    public DateTime RequestedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }

    public virtual ApplicationUser? User { get; set; }
}

public enum ExportStatus
{
    Pending,
    Processing,
    Completed,
    Failed
}
