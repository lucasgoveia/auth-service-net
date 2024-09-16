using System.Diagnostics;
using Npgsql;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace AuthService.WebApi.Configurations;

public static class OTelConfiguration
{
    private const string MassTransitSource = "MassTransit";
    private const string ServiceDeploymentEnv = "deployment.environment";

    public static IHostBuilder AddOpenTelemetrySetup(this IHostBuilder builder,
        Action<TracerProviderBuilder>? telemetryAction = null)
    {
        Activity.DefaultIdFormat = ActivityIdFormat.W3C;

        return builder.ConfigureServices((ctx, services) =>
        {
            services.AddOpenTelemetry()
                .ConfigureResource((resourceBuilder) => resourceBuilder
                    .AddService(serviceName: ctx.HostingEnvironment.ApplicationName, serviceVersion: "1.0")
                    .AddAttributes([new KeyValuePair<string, object>(ServiceDeploymentEnv, ctx.HostingEnvironment.EnvironmentName)])
                    .AddTelemetrySdk()
                    .AddEnvironmentVariableDetector())
                .WithTracing(telemetry =>
                {
                    telemetry.AddSource(ctx.HostingEnvironment.ApplicationName)
                        .AddSource(MassTransitSource)
                        .AddSource(ApiActivitySource.ServiceName)
                        .AddHttpClientInstrumentation(o => o.RecordException = true)
                        .AddNpgsql()
                        .AddRedisInstrumentation()
                        .AddAspNetCoreInstrumentation(o =>
                        {
                            const string healthPath = "/health";
                            o.RecordException = true;
                            o.Filter = context => context.Request.Path != healthPath;
                        });
                    
                    telemetryAction?.Invoke(telemetry);

                    telemetry.AddOtlpExporter();
                })
                .WithMetrics(telemetry =>
                {
                    telemetry.AddMeter(MassTransitSource)
                        .AddMeter("Microsoft.AspNetCore.Hosting")
                        .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
                        .AddMeter("Microsoft.AspNetCore.Http.Connections")
                        .AddMeter("Microsoft.AspNetCore.Routing")
                        .AddMeter("Microsoft.AspNetCore.Diagnostics")
                        .AddMeter("Microsoft.AspNetCore.RateLimiting")
                        .AddHttpClientInstrumentation()
                        .AddRuntimeInstrumentation()
                        .AddMeter("Npgsql")
                        .AddProcessInstrumentation()
                        // .AddMeter("Custom.Metrics")
                        .AddOtlpExporter();
                });
        });
    }
}