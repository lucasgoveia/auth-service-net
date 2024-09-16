using Serilog;
using Serilog.Events;
using Serilog.Sinks.OpenTelemetry;

namespace AuthService.WebApi.Configurations;

public static class LoggingConfiguration
{
    private const string ServiceNameResource = "service.name";
    private const string ServiceDeploymentEnv = "deployment.environment";
    private const string ServiceVersionResource = "service.version";
    private const string OltpEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT";

    public static IHostBuilder AddLoggingSetup(this IHostBuilder hostBuilder)
    {
        return hostBuilder.ConfigureServices((ctx, services) =>
        {
            var loggerConfiguration = new LoggerConfiguration()
                .ReadFrom.Configuration(ctx.Configuration)
                .MinimumLevel.Override("HealthChecks.UI.Core.HostedService", LogEventLevel.Warning)
                .MinimumLevel.Override("AspNetCore.HealthChecks.UI", LogEventLevel.Warning)
                .MinimumLevel.Override("HealthChecks", LogEventLevel.Warning)
                .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
                .MinimumLevel.Override("AspNetCore.HealthChecks.UI.InMemory.Storage", LogEventLevel.Warning);

            if (!ctx.HostingEnvironment.IsEnvironment("Testing"))
            {
                loggerConfiguration = loggerConfiguration.WriteTo.OpenTelemetry(options =>
                {
                    options.ResourceAttributes = new Dictionary<string, object>()
                    {
                        [ServiceNameResource] = ctx.HostingEnvironment.ApplicationName,
                        [ServiceVersionResource] = "1.0",
                        [ServiceDeploymentEnv] = ctx.HostingEnvironment.EnvironmentName
                    };
                    options.Protocol = OtlpProtocol.Grpc;
                    var extractedEndpoint = ctx.Configuration.GetValue<string>(OltpEndpoint);
                    if (!string.IsNullOrEmpty(extractedEndpoint))
                    {
                        options.Endpoint = extractedEndpoint!;
                    }
                });
            }

            var logger = loggerConfiguration
                .CreateLogger();
            
            services.AddLogging(o =>
            {
                o.ClearProviders();
                o.AddSerilog(logger);
            });
        });
    }
}