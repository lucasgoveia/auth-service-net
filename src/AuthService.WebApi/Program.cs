using AuthService.Common;
using AuthService.Mailing;
using AuthService.WebApi.Common;
using AuthService.WebApi.Configurations;
using AuthService.WebApi.Modules.Accounts;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Modules.Auth;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

builder.AddCommonServices();
builder.AddBusSetup();
builder.AddCaching();
builder.AddAuthSetup();
builder.AddDatabase();

builder.Services.AddValidatorsFromAssembly(typeof(RegisterAccountValidator).Assembly);

builder.Services.AddHttpContextAccessor();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Host.AddMailingSetup();

builder.Services.AddAccountsFunctionality();
builder.Services.AddAuthFunctionality();


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