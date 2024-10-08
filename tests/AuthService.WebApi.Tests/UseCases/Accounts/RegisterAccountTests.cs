﻿using System.Data;
using System.Net;
using System.Net.Http.Json;
using AuthService.Common.Consts;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Messages.Commands;
using AuthService.WebApi.Modules.Accounts.UseCases;
using AuthService.WebApi.Tests.Utils;
using Dapper;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.WebApi.Tests.UseCases.Accounts;

public class RegisterAccountTests : TestBase, IClassFixture<IntegrationTestFactory>
{
    public RegisterAccountTests(IntegrationTestFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Register_account_with_valid_data_returns_success()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Register_account_with_invalid_email_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_with_weak_password_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "teste@example.com",
            Password = "test",
            Name = "Test User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_with_existing_email_returns_bad_request()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Act
        var response = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_account_should_return_access_token()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };

        // Act
        var res = await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);
        var resContent = await res.Content.ReadFromJsonAsync<RegisterAccountResponse>();
        
        // Assert
        res.Should().BeSuccessful();
        resContent!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Register_account_should_send_email_verification()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        MessageBus.Messages.Should().Contain(x =>
            x is SendEmailVerification && ((SendEmailVerification)x).Email == registerAccountRequest.Email);
    }

    [Fact]
    public async Task Register_account_should_save_identity_to_db()
    {
        // Arrange
        var registerAccountRequest = new RegisterAccount
        {
            Email = "test@example.com",
            Password = "Test1234!_345ax1",
            Name = "Test User"
        };

        // Act
        await Client.PostAsJsonAsync("/accounts/register", registerAccountRequest);

        // Assert
        (await Factory.Services.GetRequiredService<IDbConnection>()
                .QuerySingleOrDefaultAsync<int>($"SELECT COUNT(*) FROM {TableNames.Identities} WHERE username = @Email",
                    new { registerAccountRequest.Email }))
            .Should().Be(1);
    }
}