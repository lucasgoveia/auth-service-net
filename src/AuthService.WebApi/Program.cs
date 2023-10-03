using AuthService.Mailing;
using AuthService.WebApi.Configurations;
using AuthService.WebApi.Modules.Accounts;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

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

app.UseAuthentication();
app.UseAuthorization();

app.MapAccountsEndpoints();
app.MapAuthEndpoints();

app.UseHealthChecks("/health");

app.Run();