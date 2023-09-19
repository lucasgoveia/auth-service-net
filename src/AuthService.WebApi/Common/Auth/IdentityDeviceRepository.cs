﻿using System.Data;
using AuthService.WebApi.Common.Consts;
using Dapper;

namespace AuthService.WebApi.Common.Auth;

public record IdentityDevice
{
    public int Id { get; set; }
    public required string DeviceFingerprint { get; init; }
    public required long IdentityId { get; init; }
    public required string Name { get; init; }
    public required string IpAddress { get; init; }
}

public interface IIdentityDeviceRepository
{
    public Task Add(IdentityDevice device);
    public Task Remove(string deviceFingerprint);
}

public class IdentityDeviceRepository : IIdentityDeviceRepository
{
    private readonly IDbConnection _dbConnection;

    public IdentityDeviceRepository(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task Add(IdentityDevice device)
    {
        await _dbConnection.ExecuteAsync(
            $"INSERT INTO {TableNames.IdentityDevices} (device_fingerprint, identity_id, name, ip_address) VALUES (@DeviceFingerprint, @IdentityId, @Name, @IpAddress);",
            new
            {
                device.DeviceFingerprint,
                device.IdentityId,
                device.Name,
                device.IpAddress
            });
    }

    public async Task Remove(string deviceFingerprint)
    {
        await _dbConnection.ExecuteAsync($"DELETE FROM {TableNames.IdentityDevices} WHERE device_fingerprint = @deviceFingerprint;", new { deviceFingerprint });
    }
}