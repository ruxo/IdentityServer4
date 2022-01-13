using IdentityServer4.Models.Contexts;

namespace IdentityServer4.Services;

/// <summary>
/// <see cref="AuthContext"/> parser
/// </summary>
public interface IAuthContextParser
{
    /// <summary>
    /// Transform API request parameters into an AuthContext
    /// </summary>
    /// <param name="parameters">API parameters usually retrieved from the query string of any authentication endpoint</param>
    /// <returns></returns>
    ValueTask<AuthContext> CreateContext(ApiParameters parameters);
}