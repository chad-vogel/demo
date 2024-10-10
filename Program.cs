using System.Data.Common;
using System.Data.SqlClient;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Diagnostics.HealthChecks;
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
var telemetryClient =
    new TelemetryClient(builder.Services.BuildServiceProvider().GetRequiredService<TelemetryConfiguration>());

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
builder.Services.AddKeyedSingleton<Func<Task<string>>>("SqlConnectionString", (sp, _) => async () =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    if (isDevelopment)
    {
        logger.LogInformation("Using local development configuration for SQL connection string.");
        telemetryClient.TrackEvent("UsingLocalSqlConfig");
        return configuration.GetConnectionString("BaseSqlConnectionString");
    }

    logger.LogInformation("Retrieving SQL credentials from Azure Key Vault.");
    telemetryClient.TrackEvent("UsingAzureKeyVaultForSql");
    var secretClient = sp.GetRequiredService<SecretClient>();
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
});

// Register a keyed service to build the MongoDB connection string based on the environment
builder.Services.AddKeyedSingleton<Func<Task<string>>>("MongoConnectionString", (sp, _) => async () =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    var baseConnectionString = configuration.GetConnectionString("MongoDbBaseConnectionString");
    if (string.IsNullOrEmpty(baseConnectionString))
    {
        logger.LogError("MongoDB base connection string is not configured properly.");
        throw new InvalidOperationException("MongoDB base connection string is missing.");
    }

    if (isDevelopment)
    {
        logger.LogInformation("Using local development configuration for MongoDB connection string.");
        telemetryClient.TrackEvent("UsingLocalMongoConfig");
        return baseConnectionString;
    }

    logger.LogInformation("Retrieving MongoDB credentials from Azure Key Vault.");
    telemetryClient.TrackEvent("UsingAzureKeyVaultForMongo");
    var secretClient = sp.GetRequiredService<SecretClient>();

    try
    {
        var mongoUserSecret = await secretClient.GetSecretAsync("MongoUserId");
        var mongoPasswordSecret = await secretClient.GetSecretAsync("MongoPassword");

        var userId = mongoUserSecret?.Value?.ToString();
        var password = mongoPasswordSecret?.Value?.ToString();

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(password))
        {
            logger.LogError("MongoDB credentials are missing in Key Vault.");
            throw new InvalidOperationException("MongoDB credentials are missing.");
        }

        var mongoConnectionString = $"{baseConnectionString}?authSource=admin&username={userId}&password={password}";
        logger.LogInformation("MongoDB connection string successfully built.");
        telemetryClient.TrackMetric("MongoConnectionStringBuilt", 1);

        return mongoConnectionString;
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to retrieve MongoDB credentials from Key Vault.");
        telemetryClient.TrackException(ex);
        throw new InvalidOperationException("Failed to build MongoDB connection string.", ex);
    }
});

// Register a keyed service for Func<Task<DbConnection>> to use the SQL connection string
builder.Services.AddKeyedSingleton<Func<Task<DbConnection>>>("SqlDbConnection", (sp, _) => async () =>
{
    var logger = sp.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Establishing SQL database connection...");

    try
    {
        var connectionStringFunc = sp.GetKeyedService<Func<Task<string>>>("SqlConnectionString");
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

// Register MongoDB client using the Mongo connection string
builder.Services.AddSingleton<IMongoClient>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<Program>>();
    var connectionStringFunc = sp.GetKeyedService<Func<Task<string>>>("MongoConnectionString");
    var mongoConnectionString = connectionStringFunc().GetAwaiter().GetResult();

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
app.MapGet("/api/status", () => { return Results.Ok(new { Status = "API is running" }); });

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

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Checking SQL Server health...");

        try
        {
            await using var connection = await _dbConnectionFunc();
            return HealthCheckResult.Healthy("SQL Server is healthy");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SQL Server health check failed.");
            return HealthCheckResult.Unhealthy("SQL Server is unhealthy", ex);
        }
    }
}