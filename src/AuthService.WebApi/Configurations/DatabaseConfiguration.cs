using System.Data;
using Dapper;
using Npgsql;

namespace AuthService.WebApi.Configurations;

public static class DatabaseConfiguration
{
    public static void AddDatabase(this WebApplicationBuilder builder)
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;
        SqlMapper.AddTypeHandler(new SnowflakeIdTypeHandler());
        builder.Services.AddTransient<IDbConnection>(_ =>
            new NpgsqlConnection(builder.Configuration.GetConnectionString("DefaultConnection")));
    }
}