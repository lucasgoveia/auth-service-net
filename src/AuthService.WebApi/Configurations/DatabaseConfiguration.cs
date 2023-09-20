using System.Data;
using Npgsql;

namespace AuthService.WebApi.Configurations;

public static class DatabaseConfiguration
{
    public static void AddDatabase(this WebApplicationBuilder builder)
    {
        Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;
        builder.Services.AddScoped<IDbConnection>(_ =>
            new NpgsqlConnection(builder.Configuration.GetConnectionString("DefaultConnection")));
    }
}