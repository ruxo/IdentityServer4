using System.Security.Claims;
using IdentityModel;

namespace IdentityServer4.Models;

/// <summary>
/// Claim collection
/// </summary>
public class ClaimCollection : System.Collections.Generic.HashSet<Claim>
{
    /// <summary>
    /// New claim collection
    /// </summary>
    public ClaimCollection() : base(new ClaimComparer()) {}
    /// <summary>
    /// New claim with existing data.
    /// </summary>
    /// <param name="data"></param>
    public ClaimCollection(IEnumerable<Claim> data) : base(data, new ClaimComparer()) {}
}