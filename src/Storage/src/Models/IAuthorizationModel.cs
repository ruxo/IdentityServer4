using System.Security.Claims;

namespace IdentityServer4.Models;

/// <summary>
/// Common model for Authorization
/// </summary>
public interface IAuthorizationModel
{
    /// <summary>
    /// Client Identifier
    /// </summary>
    string ClientId { get; }
    /// <summary>
    /// Description of this model
    /// </summary>
    Option<string> Description { get; }
    /// <summary>
    /// Gets the subject, which is available only when it is authorized.
    /// </summary>
    ClaimsPrincipal Subject { get; }
    /// <summary>
    /// Requested scopes
    /// </summary>
    string[] Scopes { get; }
}