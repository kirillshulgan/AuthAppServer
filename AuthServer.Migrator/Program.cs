using AuthServer.Infrastructure.Data;
using AuthServer.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        // Используем явную строку подключения
        var connectionString = context.Configuration.GetConnectionString("DefaultConnection")
            ?? "Host=postgres;Port=5432;Database=auth_server_db;Username=postgres;Password=postgres;GSS Encryption Mode=Disable;Keepalive=30";

        services.AddDbContext<AuthDbContext>(options =>
        {
            options.UseNpgsql(connectionString);
            options.UseOpenIddict<Guid>();
        });

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<AuthDbContext>()
                       .ReplaceDefaultEntities<Guid>();
            });

        services.AddHostedService<DbMigratorHostedService>();
    })
    .Build();

await host.RunAsync();
