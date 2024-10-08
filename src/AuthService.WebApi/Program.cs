using AuthService.Mailing;
using AuthService.WebApi.Configurations;
using AuthService.WebApi.Modules.Accounts;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth;
using FluentValidation;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors();
builder.Services.AddApplicationInsightsTelemetry();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("DefaultConnection")!)
    .AddRedis(builder.Configuration.GetConnectionString("RedisConnection")!);

builder.AddCommonServices();
builder.AddBusSetup();
builder.AddCaching();
builder.AddAuthSetup();
builder.AddDatabase();
builder.Host.AddLoggingSetup();
builder.Host.AddOpenTelemetrySetup();

builder.Services.AddValidatorsFromAssembly(typeof(RegisterAccountValidator).Assembly);

builder.Services.AddHttpContextAccessor();

builder.Host.AddMailingSetup();

builder.Services.AddAccountsFunctionality();
builder.Services.AddAuthFunctionality();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseHttpsRedirection();
}

app.UseCors(c =>
{
    c.AllowAnyHeader();
    c.AllowAnyMethod();
    c.SetIsOriginAllowedToAllowWildcardSubdomains();
    c.WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? []);
    c.AllowCredentials();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapAccountsEndpoints();
app.MapAuthEndpoints();

app.MapHealthChecks("/health",
    new HealthCheckOptions
    {
        Predicate = _ => true,
        ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse,
        AllowCachingResponses = false,
    });

app.Run();