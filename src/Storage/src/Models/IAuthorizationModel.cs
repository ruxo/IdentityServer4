
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
    /// Requested scopes
    /// </summary>
    string[] Scopes { get; }
}