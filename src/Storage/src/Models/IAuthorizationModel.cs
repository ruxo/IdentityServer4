using System.Collections.Generic;
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
    string? ClientId { get; }
    /// <summary>
    /// Description of this model
    /// </summary>
    string Description { get; }
    /// <summary>
    /// Gets the subject.
    /// </summary>
    ClaimsPrincipal Subject { get; }
    /// <summary>
    /// Requested scopes
    /// </summary>
    IEnumerable<string> Scopes { get; }
}