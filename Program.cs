using System.Data.Common;
using System.Data.SqlClient;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Configure Application Insights
builder.Services.AddApplicationInsightsTelemetry(options =>
{
    options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
});

// Set up TelemetryClient for custom metrics and events
var telemetryClient = new TelemetryClient(builder.Services.BuildServiceProvider().GetRequiredService<TelemetryConfiguration>());

// Determine if the application is running locally
var isDevelopment = builder.Environment.IsDevelopment();

if (!isDevelopment)
{
    // Add Azure Key Vault integration only when not in local development
    var keyVaultUri = builder.Configuration["KeyVault:VaultUri"];
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential());
    
    // Register the SecretClient for Azure Key Vault
    builder.Services.AddSingleton(new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential()));
}

// Register a keyed service to build the SQL connection string based on the environment
builder.Services.AddSingleton<Func<Task<string>>>(async () =>
{
    var configuration = builder.Configuration;
    var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();

    if (isDevelopment)
    {
        logger.LogInformation("Using local development configuration for SQL connection string.");
        telemetryClient.TrackEvent("UsingLocalSqlConfig");
        return configuration.GetConnectionString("BaseSqlConnectionString");
    }
    else
    {
        logger.LogInformation("Retrieving SQL credentials from Azure Key Vault.");
        telemetryClient.TrackEvent("UsingAzureKeyVaultForSql");
        var secretClient = builder.Services.BuildServiceProvider().GetRequiredService<SecretClient>();
        var baseConnectionString = configuration.GetConnectionString("BaseSqlConnectionString");

        var userIdSecret = await secretClient.GetSecretAsync("UserId");
        var passwordSecret = await secretClient.GetSecretAsync("Password");

        var userId = userIdSecret.Value;
        var password = passwordSecret.Value;

        var connectionStringBuilder = new SqlConnectionStringBuilder(baseConnectionString)
        {
            UserID = userId.Value,
            Password = password.Value
        };

        logger.LogInformation("SQL connection string successfully built.");
        telemetryClient.TrackMetric("SqlConnectionStringBuilt", 1);
        return connectionStringBuilder.ConnectionString;
    }
});

// Register a keyed service for Func<Task<DbConnection>> to use the connection string
builder.Services.AddSingleton<Func<Task<DbConnection>>>(async () =>
{
    var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Establishing SQL database connection...");
    
    try
    {
        var connectionStringFunc = builder.Services.BuildServiceProvider().GetRequiredService<Func<Task<string>>>();
        var connectionString = await connectionStringFunc();
        var connection = new SqlConnection(connectionString);

        await connection.OpenAsync();
        logger.LogInformation("SQL database connection established successfully.");
        telemetryClient.TrackMetric("SqlDatabaseConnectionEstablished", 1);
        return connection;
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to establish SQL database connection.");
        telemetryClient.TrackException(ex);
        telemetryClient.TrackMetric("SqlDatabaseConnectionFailed", 1);
        throw;
    }
});

// Register MongoDB client based on the environment
builder.Services.AddSingleton<IMongoClient>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<Program>>();
    var configuration = sp.GetRequiredService<IConfiguration>();
    var mongoConnectionString = configuration["MongoDb:ConnectionString"];
    logger.LogInformation("Configuring MongoDB client.");
    telemetryClient.TrackEvent("ConfiguringMongoDbClient");
    return new MongoClient(mongoConnectionString);
});

// Register the health checks for SQL Server and MongoDB
builder.Services.AddHealthChecks()
    .AddCheck<SqlServerHealthCheck>("SQL Server")
    .AddMongoDb(builder.Configuration["MongoDb:ConnectionString"], name: "MongoDB");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(options =>
    {
        builder.Configuration.Bind("AzureAd", options);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true
        };
        telemetryClient.TrackEvent("JwtAuthenticationConfigured");
    }, options => builder.Configuration.Bind("AzureAd", options));

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (!isDevelopment)
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    telemetryClient.TrackEvent("ProductionExceptionHandlerConfigured");
}

if (isDevelopment)
{
    app.UseSwagger();
    app.UseSwaggerUI();
    telemetryClient.TrackEvent("SwaggerConfiguredForDevelopment");
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapHealthChecks("/health");

// Example Minimal API endpoint
app.MapGet("/api/status", () =>
{
    return Results.Ok(new { Status = "API is running" });
});

var cancellationTokenSource = new CancellationTokenSource();
var cancellationToken = cancellationTokenSource.Token;

app.Lifetime.ApplicationStopping.Register(() => OnShutdown(cancellationTokenSource, telemetryClient));

var runTask = app.RunAsync(cancellationToken);

Console.CancelKeyPress += (sender, eventArgs) =>
{
    telemetryClient.TrackEvent("ApplicationShutdownRequested");
    cancellationTokenSource.Cancel();
    eventArgs.Cancel = true;
};

try
{
    await runTask;
}
catch (OperationCanceledException)
{
    telemetryClient.TrackEvent("ApplicationCanceled");
}
finally
{
    cancellationTokenSource.Dispose();
}

void OnShutdown(CancellationTokenSource cts, TelemetryClient telemetry)
{
    telemetry.TrackEvent("ApplicationShutdown");
    cts.Cancel();
}

// Health check class for SQL Server
public class SqlServerHealthCheck : IHealthCheck
{
    private readonly Func<Task<DbConnection>> _dbConnectionFunc;
    private readonly ILogger<SqlServerHealthCheck> _logger;

    public SqlServerHealthCheck(Func<Task<DbConnection>> dbConnectionFunc, ILogger<SqlServerHealthCheck> logger)
    {
        _dbConnectionFunc = dbConnectionFunc;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Checking SQL Server health...");

        try
        {
            using var connection = await _dbConnectionFunc();
            return HealthCheckResult.Healthy("SQL Server is healthy");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SQL Server health check failed.");
            return HealthCheckResult.Unhealthy("SQL Server is unhealthy", ex);
        }
    }
}