using System.Data;
using System.Data.Common;
using FluentValidation;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Data.SqlClient;
using Polly;

namespace Processer;

/// <summary>
///     Represents a command in the CQRS pattern.
/// </summary>
public interface ICommand
{
}

/// <summary>
///     Handler interface for executing commands.
/// </summary>
/// <typeparam name="TCommand">The command to handle.</typeparam>
public interface ICommandHandler<TCommand> where TCommand : ICommand
{
    Task Execute(TCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
///     Represents a query in the CQRS pattern.
/// </summary>
/// <typeparam name="TValue">The type of the result.</typeparam>
public interface IQuery<TValue>
{
}

/// <summary>
///     Handler interface for handling queries.
/// </summary>
/// <typeparam name="TQuery">The query to handle.</typeparam>
/// <typeparam name="TValue">The result type of the query.</typeparam>
public interface IQueryHandler<TQuery, TValue> where TQuery : IQuery<TValue>
{
    Task<TValue> Query(TQuery query, CancellationToken cancellationToken = default);
}

/// <summary>
///     Dispatcher interface for handling commands and queries in the CQRS pattern.
/// </summary>
public interface IDispatcher
{
    Task Publish<TCommand>(TCommand command, CancellationToken cancellationToken = default) where TCommand : ICommand;
    Task<TValue> Query<TValue>(IQuery<TValue> query, CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<TKey, TValue>> Query<TKey, TValue>(IQuery<IReadOnlyDictionary<TKey, TValue>> query,
        CancellationToken cancellationToken = default);
}

/// <summary>
///     Service for validating objects using FluentValidation.
/// </summary>
/// <typeparam name="T">The type of object to validate.</typeparam>
public class ValidationService<T>(IValidator<T> validator)
    where T : class
{
    public async Task ValidateAsync(T instance, CancellationToken cancellationToken)
    {
        if (validator != null)
        {
            var result = await validator.ValidateAsync(instance, cancellationToken);
            if (!result.IsValid) throw new ValidationException(result.Errors);
        }
    }
}

/// <summary>
///     Factory interface for creating database connections for command handling.
/// </summary>
public interface ICommandDbConnectionFactory
{
    Task<DbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default);
}

public class CommandDbConnectionFactory(string commandConnectionString) : ICommandDbConnectionFactory
{
    private readonly string _commandConnectionString = $"{commandConnectionString};Pooling=true";

    public async Task<DbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqlConnection(_commandConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

/// <summary>
///     Factory interface for creating database connections for query handling.
/// </summary>
public interface IQueryDbConnectionFactory
{
    Task<DbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default);
}

public class QueryDbConnectionFactory(string queryConnectionString) : IQueryDbConnectionFactory
{
    private readonly string _queryConnectionString = $"{queryConnectionString};Pooling=true";

    public async Task<DbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqlConnection(_queryConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

public class SqlServerDispatcher(IServiceProvider services) : IDispatcher
{
    private readonly IServiceProvider _services = services ?? throw new ArgumentNullException(nameof(services));

    public Task Publish<TCommand>(TCommand command, CancellationToken cancellationToken = default)
        where TCommand : ICommand
    {
        var handler = _services.GetRequiredService<ICommandHandler<TCommand>>();
        return handler.Execute(command, cancellationToken);
    }

    public Task<TValue> Query<TValue>(IQuery<TValue> query, CancellationToken cancellationToken = default)
    {
        var handlerType = typeof(IQueryHandler<,>).MakeGenericType(query.GetType(), typeof(TValue));
        var handler = (IQueryHandler<IQuery<TValue>, TValue>)_services.GetRequiredService(handlerType);
        return handler.Query(query, cancellationToken);
    }

    public Task<IReadOnlyDictionary<TKey, TValue>> Query<TKey, TValue>(
        IQuery<IReadOnlyDictionary<TKey, TValue>> query, CancellationToken cancellationToken = default)
    {
        var handlerType =
            typeof(IQueryHandler<,>).MakeGenericType(query.GetType(), typeof(IReadOnlyDictionary<TKey, TValue>));
        var handler = (IQueryHandler<IQuery<IReadOnlyDictionary<TKey, TValue>>, IReadOnlyDictionary<TKey, TValue>>)
            _services.GetRequiredService(handlerType);
        return handler.Query(query, cancellationToken);
    }
}

public abstract class SqlServerCommandHandler<TCommand>(
    IServiceProvider services,
    ICommandDbConnectionFactory connectionFactory,
    ValidationService<TCommand> validationService,
    ILogger<SqlServerCommandHandler<TCommand>> logger,
    TelemetryClient telemetryClient // Application Insights client for tracing and metrics
) : AbstractValidator<TCommand>, ICommandHandler<TCommand> where TCommand : class, ICommand
{
    private readonly IAsyncPolicy _circuitBreakerPolicy = Policy
        .Handle<DbException>()
        .CircuitBreakerAsync(2, TimeSpan.FromMinutes(1),
            (exception, duration) =>
            {
                logger.LogWarning("Circuit breaker opened due to {Exception}. It will remain open for {Duration}.",
                    exception, duration);
            },
            () => logger.LogInformation("Circuit breaker reset and closed."),
            () => logger.LogInformation("Circuit breaker is half-open; testing recovery."));

    private readonly ICommandDbConnectionFactory _connectionFactory =
        connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));

    private readonly ILogger<SqlServerCommandHandler<TCommand>> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly IAsyncPolicy _retryPolicy = Policy
        .Handle<DbException>()
        .Or<TimeoutException>()
        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));

    private readonly TelemetryClient _telemetryClient = telemetryClient;

    private readonly IAsyncPolicy _timeoutPolicy = Policy.TimeoutAsync(30);

    private readonly ValidationService<TCommand> _validationService =
        validationService ?? throw new ArgumentNullException(nameof(validationService));

    public async Task Execute(TCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command, nameof(command));

        using var operation =
            _telemetryClient.StartOperation<RequestTelemetry>($"Execute Command: {typeof(TCommand).Name}");

        _logger.LogInformation("Executing command {CommandName}", typeof(TCommand).Name);

        _telemetryClient.TrackEvent("Command Executed", new Dictionary<string, string>
        {
            { "CommandName", typeof(TCommand).Name }
        });

        await _validationService.ValidateAsync(command, cancellationToken).ConfigureAwait(false);

        await using var connection =
            await _connectionFactory.CreateConnectionAsync(cancellationToken).ConfigureAwait(false);

        await using var transaction = await connection
            .BeginTransactionAsync(IsolationLevel.Unspecified, cancellationToken).ConfigureAwait(false);

        try
        {
            await _retryPolicy.WrapAsync(_timeoutPolicy).WrapAsync(_circuitBreakerPolicy).ExecuteAsync(async () =>
            {
                await Handle(command, connection, cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            });

            _logger.LogInformation("Command {CommandName} executed successfully", typeof(TCommand).Name);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing command {CommandName}", typeof(TCommand).Name);
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    protected abstract Task Handle(TCommand command, IDbConnection connection,
        CancellationToken cancellationToken = default);
}

public abstract class SqlServerBaseQueryHandler<TQuery, TValue>(
    IServiceProvider services,
    IQueryDbConnectionFactory connectionFactory,
    ValidationService<TQuery> validationService,
    ILogger<SqlServerBaseQueryHandler<TQuery, TValue>> logger,
    TelemetryClient telemetryClient // Application Insights client for tracing and metrics
) : AbstractValidator<TQuery>, IQueryHandler<TQuery, TValue> where TQuery : class, IQuery<TValue>
{
    private readonly IAsyncPolicy _circuitBreakerPolicy = Policy
        .Handle<DbException>()
        .CircuitBreakerAsync(2, TimeSpan.FromMinutes(1),
            (exception, duration) =>
            {
                logger.LogWarning("Circuit breaker opened due to {Exception}. It will remain open for {Duration}.",
                    exception, duration);
            },
            () => logger.LogInformation("Circuit breaker reset and closed."),
            () => logger.LogInformation("Circuit breaker is half-open; testing recovery."));

    private readonly IQueryDbConnectionFactory _connectionFactory =
        connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));

    private readonly ILogger<SqlServerBaseQueryHandler<TQuery, TValue>> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly IAsyncPolicy _retryPolicy = Policy
        .Handle<DbException>()
        .Or<TimeoutException>()
        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2,
            retryAttempt)));

    private readonly TelemetryClient _telemetryClient = telemetryClient;

    private readonly IAsyncPolicy _timeoutPolicy = Policy.TimeoutAsync(30);

    private readonly ValidationService<TQuery> _validationService =
        validationService ?? throw new ArgumentNullException(nameof(validationService));

    public async Task<TValue> Query(TQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query, nameof(query));

        using var operation =
            _telemetryClient.StartOperation<RequestTelemetry>($"Execute Query: {typeof(TQuery).Name}");

        _logger.LogInformation("Executing query {QueryName}", typeof(TQuery).Name);

        _telemetryClient.TrackEvent("Query Executed", new Dictionary<string, string>
        {
            { "QueryName", typeof(TQuery).Name }
        });

        await _validationService.ValidateAsync(query, cancellationToken).ConfigureAwait(false);

        return await _retryPolicy.WrapAsync(_timeoutPolicy).WrapAsync(_circuitBreakerPolicy).ExecuteAsync(async () =>
        {
            await using var connection =
                await _connectionFactory.CreateConnectionAsync(cancellationToken).ConfigureAwait(false);

            return await Handle(query, connection, cancellationToken).ConfigureAwait(false);
        });
    }

    protected abstract Task<TValue> Handle(TQuery query, IDbConnection connection,
        CancellationToken cancellationToken = default);
}