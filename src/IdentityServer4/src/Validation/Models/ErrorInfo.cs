using System;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Basic debug information
/// </summary>
public interface IBasicDebugInfo
{
    /// <summary>
    /// Error code
    /// </summary>
    string Error { get; }

    /// <summary>
    /// Error description
    /// </summary>
    Option<string> ErrorDescription { get; }

    /// <summary>
    /// Additional debug info
    /// </summary>
    Option<object> DebugInfo { get; }
}

/// <summary>
/// Error information
/// </summary>
public record ErrorInfo(string Error = ErrorInfo.NotSpecified, string? ErrorDescription = null)
{
    /// <summary>
    /// Error not specified due to dev's laziness 🙄
    /// </summary>
    public const string NotSpecified = "not-specified";
    /// <summary>
    /// Detection of inconsistency or invalid of internal stored data.
    /// </summary>
    public const string InvalidInternalData = "invalid-internal-data";
    /// <summary>
    /// User provided invalid data.
    /// </summary>
    public const string InvalidRequest = "invalid-request";
}

/// <summary>
/// An error occured from bad request data
/// </summary>
public class BadRequestException : ApplicationException, IBasicDebugInfo
{
    /// <summary>
    ///
    /// </summary>
    /// <param name="error"></param>
    /// <param name="description"></param>
    /// <param name="debugInfo"></param>
    public BadRequestException(string error, string? description = null, object? debugInfo = null) {
        Error = error;
        ErrorDescription = Optional(description!);
        DebugInfo = Optional(debugInfo!);
    }

    /// <inheritdoc />
    public string Error { get; }

    /// <inheritdoc />
    public Option<string> ErrorDescription { get; }

    /// <inheritdoc />
    public Option<object> DebugInfo { get; }
}

/// <summary>
/// Error with custom response..
/// </summary>
/// <param name="Error"></param>
/// <param name="ErrorDescription"></param>
/// <param name="CustomResponse"></param>
public record ErrorWithCustomResponse(string Error, string? ErrorDescription, Dictionary<string, object> CustomResponse) : ErrorInfo(Error, ErrorDescription)
{
    /// <summary>
    /// Create new error
    /// </summary>
    /// <param name="error"></param>
    /// <returns></returns>
    public static ErrorWithCustomResponse Create(string error) => new(error, null, new());
}