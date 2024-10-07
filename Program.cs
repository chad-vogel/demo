using System.Data.Common;
using System.Data.SqlClient;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault integration
var keyVaultUri = builder.Configuration["KeyVault:VaultUri"];
builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential());

// Register the SecretClient for Azure Key Vault
builder.Services.AddSingleton(new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential()));

// Register a keyed service to asynchronously build the SQL connection string
builder.Services.AddKeyedSingleton<Func<Task<string>>>("SqlConnection", (serviceProvider, _) => async () =>
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var secretClient = serviceProvider.GetRequiredService<SecretClient>();

    // Get the base connection string from the configuration
    var baseConnectionString = configuration.GetConnectionString("BaseSqlConnectionString");

    // Retrieve UserId and Password from Azure Key Vault asynchronously
    var userIdSecret = await secretClient.GetSecretAsync("UserId");
    var passwordSecret = await secretClient.GetSecretAsync("Password");

    // Extract the secret values
    var userId = userIdSecret.Value;
    var password = passwordSecret.Value;

    // Build the final SQL connection string using SqlConnectionStringBuilder
    var connectionStringBuilder = new SqlConnectionStringBuilder(baseConnectionString)
    {
        UserID = userId.Value,
        Password = password.Value
    };

    return connectionStringBuilder.ConnectionString;
});


// Register a keyed service for Func<Task<DbConnection>> to use the connection string
builder.Services.AddKeyedSingleton<Func<Task<DbConnection>>>("SqlDbConnection", (serviceProvider, _) => async () =>
{
    // Retrieve the connection string that was registered earlier using GetKeyedService
    var connectionStringFunc = serviceProvider.GetKeyedService<Func<Task<string>>>("SqlConnection");

    // Create a factory that returns a new SqlConnection using the retrieved connection string
    var connectionString = await connectionStringFunc();
    var connection = new SqlConnection(connectionString);

    // Open the connection asynchronously
    await connection.OpenAsync();
    
    return connection;
});


// Add Application Insights
builder.Services.AddApplicationInsightsTelemetry(options =>
{
    options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
});

// Add services to the container and configure authentication using MicrosoftIdentityWebApi
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(options =>
    {
        builder.Configuration.Bind("AzureAd", options);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true
        };
    }, options => builder.Configuration.Bind("AzureAd", options));

// Add services to the container.
builder.Services.AddAuthorization();

builder.Services.AddControllersWithViews();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();