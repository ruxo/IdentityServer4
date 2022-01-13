using System.Security.Cryptography.X509Certificates;

namespace IdentityServer4.Models;

/// <summary>
/// Tag union of possible client secrets
/// </summary>
public abstract record ClientSecret
{
    /// <summary>
    /// No Secret
    /// </summary>
    public sealed record None : ClientSecret
    {
        /// <inheritdoc />
        public override string Type => "NoSecret";
    }

    /// <summary>
    /// Shared Secret
    /// </summary>
    /// <param name="Secret"></param>
    public sealed record Shared(string Secret) : ClientSecret
    {
        /// <inheritdoc />
        public override string Type => "SharedSecret";
    }

    /// <summary>
    /// X509 Certificate
    /// </summary>
    /// <param name="Certificate"></param>
    public sealed record X509Certificate(X509Certificate2 Certificate) : ClientSecret
    {
        /// <inheritdoc />
        public override string Type => "X509Certificate";
    }

    /// <summary>
    /// Jwt Bearer
    /// </summary>
    /// <param name="Assertion"></param>
    public sealed record JwtBearer(string Assertion) : ClientSecret
    {
        /// <inheritdoc />
        public override string Type => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    }

    /// <summary>
    /// Type of the secret
    /// </summary>
    public abstract string Type { get; }
}

/// <summary>
/// Represents a client's credentials
/// </summary>
/// <param name="ClientId">the client identifier associated with this secret</param>
public readonly record struct Credentials(string ClientId, ClientSecret Secret);