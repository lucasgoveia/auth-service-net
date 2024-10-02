using System.Data;
using Dapper;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Configurations;

public class SnowflakeIdTypeHandler : SqlMapper.TypeHandler<SnowflakeId>
{
    public override void SetValue(IDbDataParameter parameter, SnowflakeId value)
    {
        parameter.Value = value.Value;
    }

    public override SnowflakeId Parse(object? value)
    {
        var idLong = (long?)value;
        return !idLong.HasValue
            ? default
            : new SnowflakeId(idLong.Value);
    }
}