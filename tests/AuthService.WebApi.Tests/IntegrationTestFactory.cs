using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using AuthService.Common.Caching;
using AuthService.Common.Messaging;
using AuthService.Common.Timestamp;
using AuthService.Consumers.CommandHandlers;
using AuthService.Mailing;
using AuthService.WebApi.Common.Devices;
using AuthService.WebApi.Tests.Fakes;
using Dapper;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using MassTransit;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using NSubstitute;
using Respawn;
using Testcontainers.PostgreSql;

namespace AuthService.WebApi.Tests;

public class IntegrationTestFactory : WebApplicationFactory<IAssemblyMarker>, IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresqlContainer = new PostgreSqlBuilder()
        .WithImage("postgres:latest")
        .WithPassword("DB_SECURE_PASSWORD")
        .WithUsername("postgres")
        .WithName($"auth-service-test-postgres-{Guid.NewGuid()}")
        .WithDatabase("auth_service_test")
        .WithPortBinding(5432, true)
        .WithCleanUp(true)
        .Build();

    private Respawner _respawner = default!;

    public readonly IEmailSender EmailSender = Substitute.For<IEmailSender>();
    public IMessageBus MessageBus => Services.GetRequiredService<IMessageBus>();

    public FakeServerDateTimeHolder DateTimeHolder => Services.GetRequiredService<FakeServerDateTimeHolder>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        using var rsa = RSA.Create(4096);
        var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        
        builder.UseEnvironment("Testing");
        Environment.SetEnvironmentVariable("JwtConfiguration__AccessTokenPrivateKey", privateKey);
        Environment.SetEnvironmentVariable("JwtConfiguration__AccessTokenPublicKey", publicKey);
        Environment.SetEnvironmentVariable("JwtConfiguration__RefreshTokenSecret",
            "REFRESH_VERY_SECURE_SECRET________SOME_MORE_BYTES_HERE");
        Environment.SetEnvironmentVariable("JwtConfiguration__AccessTokenMinutesLifetime", "5");
        Environment.SetEnvironmentVariable("JwtConfiguration__RefreshTokenHoursLifetime", "8");
        Environment.SetEnvironmentVariable("JwtConfiguration__RefreshTokenInTrustedDevicesHoursLifetime", "48");
        Environment.SetEnvironmentVariable("JwtConfiguration__RefreshTokenAllowedRenewsCount", "4");
        Environment.SetEnvironmentVariable("JwtConfiguration__Issuer", "http://localhost:7101");
        Environment.SetEnvironmentVariable("JwtConfiguration__ResetPasswordTokenMinutesLifetime", "15");
        Environment.SetEnvironmentVariable("JwtConfiguration__ResetPasswordTokenSecret", "RESET_VERY_SECURE_SECRET________SOME_MORE_BYTES_HERE");
        Environment.SetEnvironmentVariable("Cors__AllowedOrigins__0", "http://localhost:7101");
        
        Environment.SetEnvironmentVariable("ConnectionStrings__DefaultConnection", _postgresqlContainer.GetConnectionString());
        
        builder.ConfigureServices(services =>
            {
                var servicesToRemove = new List<Type>
                {
                    typeof(UtcNow),
                    typeof(IHostedService),
                    typeof(IDistributedCache),
                    typeof(IMessageBus),
                    typeof(IDbConnection),
                    typeof(ICacher),
                    typeof(IEmailSender),
                    typeof(IDeviceIdentifier),
                };
                var contextsDescriptor = services.Where(d => servicesToRemove.Contains(d.ServiceType)).ToList();
                foreach (var descriptor in contextsDescriptor)
                    services.Remove(descriptor);

                AddExtraServices(services);
            })
            .ConfigureLogging(o => o.AddFilter(loglevel => loglevel >= LogLevel.Warning));
        base.ConfigureWebHost(builder);
    }
    
    private void AddExtraServices(IServiceCollection services)
    {
        services.AddScoped<IDbConnection>(_ => new NpgsqlConnection(_postgresqlContainer.GetConnectionString()));
        services.AddSingleton<IMessageBus, FakeMessageBus>();
        services.AddSingleton<IEmailSender>(_ => EmailSender);
        services.AddSingleton<FakeServerDateTimeHolder>();
        services.AddSingleton<ICacher, FakeCacher>();
        services.AddSingleton<UtcNow>(sp => () => sp.GetRequiredService<FakeServerDateTimeHolder>().MockedUtcNow);

        services.AddSingleton<IDeviceIdentifier>(_ =>
        {
            var deviceIdentifier = Substitute.For<IDeviceIdentifier>();
            deviceIdentifier.Identify().Returns(new DeviceDto()
            {
                Fingerprint = "fingerprint",
                IpAddress = "127.0.0.1",
                UserAgent = "testing-agent"
            });

            return deviceIdentifier;
        });

        // Registers all consumers
        typeof(SendEmailVerificationConsumer).Assembly.GetTypes()
            .Where(item => item.GetInterfaces()
                               .Where(i => i.IsGenericType)
                               .Any(i => i.GetGenericTypeDefinition() == typeof(IConsumer<>)) &&
                           item is { IsAbstract: false, IsInterface: false })
            .ToList()
            .ForEach(assignedTypes =>
            {
                var serviceType = assignedTypes.GetInterfaces()
                    .First(i => i.GetGenericTypeDefinition() == typeof(IConsumer<>));
                services.AddScoped(serviceType, assignedTypes);
            });
    }

    public async Task InitializeAsync()
    {
        await _postgresqlContainer.StartAsync();
        await using var connection = new NpgsqlConnection(_postgresqlContainer.GetConnectionString());
        await connection.OpenAsync();

        await MigrateDb(connection);

        await SetupRespawnerAsync(connection);
        await ResetDatabaseAsync(connection);
    }

    public async Task MigrateDb(DbConnection conn)
    {
        var migrationsFiles = Directory.GetFiles("atlas/migrations", "*.sql");

        foreach (var migrationFile in migrationsFiles)
        {
            await using var stream = new FileStream(migrationFile, FileMode.Open, FileAccess.Read);
            using var reader = new StreamReader(stream!);
            var migrationSql = await reader.ReadToEndAsync();

            await conn.ExecuteAsync(migrationSql);
        }
    }

    public async Task ResetDatabaseAsync(DbConnection conn)
    {
        await _respawner.ResetAsync(conn);
    }

    public async Task ResetDatabaseAsync()
    {
        await using var conn = new NpgsqlConnection(_postgresqlContainer.GetConnectionString());
        await conn.OpenAsync();
        await _respawner.ResetAsync(conn);
    }

    public async Task ResetCacheAsync()
    {
        var cacher = (FakeCacher)Services.GetRequiredService<ICacher>();
        await cacher.Reset();
    }

    public async Task ResetBusAsync()
    {
        var bus = (FakeMessageBus)Services.GetRequiredService<IMessageBus>();
        await bus.Reset();
    }

    private async Task SetupRespawnerAsync(DbConnection conn)
    {
        _respawner = await Respawner.CreateAsync(conn,
            new RespawnerOptions
            {
                DbAdapter = DbAdapter.Postgres,
                SchemasToInclude = new[] { "iam" },
                WithReseed = true
            });
    }

    async Task IAsyncLifetime.DisposeAsync() => await _postgresqlContainer.DisposeAsync();
}