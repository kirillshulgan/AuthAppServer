using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace AuthServer.Infrastructure.Data;

public class AuthDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
        : base(options)
    {

    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);

        // Отключаем строгую проверку на несинхронизированные миграции
        optionsBuilder.ConfigureWarnings(warnings =>
            warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
    }

    // Кастомные DbSet
    public DbSet<EmailLoginCode> EmailLoginCodes => Set<EmailLoginCode>();
    public DbSet<PersonalDataExport> PersonalDataExports => Set<PersonalDataExport>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        // Обязательно сначала вызываем базовый метод для Identity
        base.OnModelCreating(builder);

        // Интеграция таблиц OpenIddict. 
        // Мы используем <Guid> в качестве первичного ключа для всех сущностей OpenIddict
        builder.UseOpenIddict<Guid>();

        // Переименование таблиц ASP.NET Core Identity (убираем префикс AspNet)
        builder.Entity<ApplicationUser>(b => b.ToTable("Users"));
        builder.Entity<ApplicationRole>(b => b.ToTable("Roles"));
        builder.Entity<IdentityUserClaim<Guid>>(b => b.ToTable("UserClaims"));
        builder.Entity<IdentityUserLogin<Guid>>(b => b.ToTable("UserLogins"));
        builder.Entity<IdentityUserToken<Guid>>(b => b.ToTable("UserTokens"));
        builder.Entity<IdentityUserRole<Guid>>(b => b.ToTable("UserRoles"));
        builder.Entity<IdentityRoleClaim<Guid>>(b => b.ToTable("RoleClaims"));
        //builder.Entity<IdentityUserPasskey<Guid>>(b =>
        //{
        //    b.ToTable("UserPasskeys");

        //    // В .NET 10 ключом является составной идентификатор из CredentialId
        //    // Если Entity Framework не находит CredentialId, это значит мы должны использовать
        //    // базовую логику IdentityDbContext. 
        //    // К счастью, мы можем просто сказать EF Core не использовать Keyless 
        //    // или задать композитный ключ
        //    b.HasKey(p => new { p.UserId, p.CredentialId });

        //    // И опционально, указываем размер колонки CredentialId, если это массив байт или строка
        //});

        // Настройка Soft Delete (глобальный фильтр)
        builder.Entity<ApplicationUser>()
            .HasQueryFilter(u => !u.IsDeleted);

        // Конфигурация EmailLoginCode
        builder.Entity<EmailLoginCode>(b =>
        {
            b.ToTable("EmailLoginCodes");
            b.HasKey(e => e.Id);
            b.HasOne(e => e.User)
             .WithMany(u => u.EmailLoginCodes)
             .HasForeignKey(e => e.UserId)
             .IsRequired(false)
             .OnDelete(DeleteBehavior.Cascade);
            b.HasIndex(e => e.Email); // Быстрый поиск по Email
        });

        // Конфигурация аудита (не делаем FK на Users, чтобы логи сохранялись даже при удалении)
        builder.Entity<AuditLog>(b =>
        {
            b.ToTable("AuditLogs");
            b.HasKey(a => a.Id);
            b.HasIndex(a => a.UserId);
            b.HasIndex(a => a.Action);
        });

        builder.Entity<PersonalDataExport>(b =>
        {
            b.ToTable("PersonalDataExports");
            b.HasKey(e => e.Id);
            b.HasOne(e => e.User)
             .WithMany()
             .HasForeignKey(e => e.UserId)
             .IsRequired(false)
             .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
