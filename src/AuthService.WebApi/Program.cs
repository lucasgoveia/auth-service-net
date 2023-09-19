using System.Data;
using AuthService.Mailing;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Security;
using AuthService.WebApi.Common.Timestamp;
using AuthService.WebApi.Configurations;
using AuthService.WebApi.Modules.Accounts;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth;
using FluentValidation;
using IdGen;
using IdGen.DependencyInjection;
using Npgsql;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddValidatorsFromAssembly(typeof(RegisterAccountValidator).Assembly);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.AddBusSetup();

builder.Services.AddMailingSetup();

builder.Services.AddScoped<IDbConnection>(_ =>
    new NpgsqlConnection(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("RedisConnection")!));
builder.Services.AddSingleton<ICacher, RedisCacher>();

builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<UtcNow>(_ => TimestampUtils.UtcNow);

builder.Services.AddIdGen(1,
    () => new IdGeneratorOptions(new IdStructure(41, 8, 14),
        new DefaultTimeSource(new DateTimeOffset(2023, 08, 01, 0, 0, 0, TimeSpan.Zero)))
);
builder.Services.AddSingleton<GenerateId>(sp => () => Task.FromResult(sp.GetRequiredService<IdGenerator>().CreateId()));

builder.AddAuthSetup();

builder.Services.AddAccountsFunctionality();
builder.Services.AddAuthFunctionality();

builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapAccountsEndpoints();
app.MapAuthEndpoints();

app.Run();