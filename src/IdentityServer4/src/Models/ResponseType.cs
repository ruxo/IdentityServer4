using System;
using System.Linq;
using IdentityModel;
using IdentityServer4.Extensions;

namespace IdentityServer4.Models;

/// <summary>
/// Represent OIDC response_type. See https://openid.net/specs/openid-connect-core-1_0.html#Authentication
/// </summary>
public readonly record struct ResponseType(bool Code, bool Token, bool IdToken)
{
    /// <summary>
    /// Supported response types
    /// </summary>
    public static readonly string[] Supported ={ OidcConstants.ResponseTypes.Code, OidcConstants.ResponseTypes.Token, OidcConstants.ResponseTypes.IdToken };

    /// <summary>
    /// Create a new, valid Response Type instance.
    /// </summary>
    /// <param name="types">response_type values</param>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static ResponseType Create(IEnumerable<string> types) {
        var t = types.ToArray();
        if (!IsValid(t)) throw new ArgumentOutOfRangeException(nameof(types), "Invalid OIDC response type");
        var hasCode = t.Contains(OidcConstants.ResponseTypes.Code);
        var hasToken = t.Contains(OidcConstants.ResponseTypes.Token);
        var hasIdToken = t.Contains(OidcConstants.ResponseTypes.IdToken);
        return new(hasCode, hasToken, hasIdToken);
    }

    /// <summary>
    /// Create a <see cref="ResponseType"/> instance from a response type string.
    /// </summary>
    /// <param name="responseType"></param>
    /// <returns></returns>
    public static ResponseType Create(string responseType) => Create(responseType.FromSpaceSeparatedString());

    /// <summary>
    /// Has code
    /// </summary>
    public bool HasCode => Code;
    /// <summary>
    /// Has 'token'
    /// </summary>
    public bool HasToken => Token;
    /// <summary>
    /// Has 'id_token'
    /// </summary>
    public bool HasIdToken => IdToken;

    /// <summary>
    /// Gets a value indicating whether an access token was requested.
    /// </summary>
    public bool AccessTokenNeeded => Code || Token && IdToken;

    /// <summary>
    /// Valid type combinations
    /// </summary>
    public static bool IsValid(IEnumerable<string> types) {
        var typeSeq = Seq(types);
        return typeSeq.Any() && typeSeq.All(t => t is OidcConstants.ResponseTypes.Code or OidcConstants.ResponseTypes.Token or OidcConstants.ResponseTypes.IdToken);
    }

    /// <summary>
    /// Get grant_type
    /// </summary>
    public string GetGrantType() =>
        !Token && !IdToken
            ? GrantType.AuthorizationCode
            : Code ? GrantType.Hybrid : GrantType.Implicit;

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public Constants.ScopeRequirement GetScopeRequirement() =>
        !Token && !IdToken  ? Constants.ScopeRequirement.None
        : !Code && !IdToken ? Constants.ScopeRequirement.ResourceOnly
        : !Code && !Token   ? Constants.ScopeRequirement.IdentityOnly
                              : Constants.ScopeRequirement.Identity;

    /// <summary>
    /// String representation of ResponseType
    /// </summary>
    /// <returns></returns>
    public override string ToString() => Serialize().Join(' ');

    // generated from GitHub Copilot!
    IEnumerable<string> Serialize() {
        if (Code) yield return OidcConstants.ResponseTypes.Code;
        if (Token) yield return OidcConstants.ResponseTypes.Token;
        if (IdToken) yield return OidcConstants.ResponseTypes.IdToken;
    }
}