using System.Collections.Immutable;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Primitives;

namespace IdentityServer4.Models.Contexts;

/// <summary>
/// Parsed authorization request parameters
/// </summary>
/// <param name="ResponseType"></param>
/// <param name="GrantType"></param>
/// <param name="ResponseMode"></param>
/// <param name="ClientId"></param>
/// <param name="Scopes"></param>
/// <param name="ParsedScopes"></param>
/// <param name="Resources"></param>
/// <param name="Client"></param>
/// <param name="AcrValues">Authentication Context Reference classes</param>
/// <param name="RedirectUri"></param>
/// <param name="MaxAge"></param>
/// <param name="State"></param>
/// <param name="Pkce"></param>
/// <param name="Nonce"></param>
public sealed record AuthContext(ResponseType ResponseType, string GrantType, string ResponseMode, string ClientId, ImmutableHashSet<string> Scopes,
                                 ParsedScopeValue[] ParsedScopes,
                                 Resource[] Resources, Client Client, string[] AcrValues, string RedirectUri, Option<int> MaxAge, Option<string> State, Option<PkceData> Pkce,
                                 Option<string> Nonce, Option<string> LoginHint, ImmutableHashSet<string> PromptModes, Option<string> UiLocales, Option<string> DisplayMode,
                                 Option<string> Request, Option<string> RequestUri, (string Key, string Value)[] AdditionalParameters)
{
    /// <summary>
    /// Get Identity Provider from ACR
    /// </summary>
    /// <returns></returns>
    public static Option<string> GetIdp(IEnumerable<string> acrValues) => GetPrefixedAcrValue(acrValues, Constants.KnownAcrValues.HomeRealm);

    /// <summary>
    /// Get Identity Provider from ACR
    /// </summary>
    /// <returns></returns>
    public Option<string> GetIdp() => GetIdp(AcrValues);

    /// <summary>
    ///
    /// </summary>
    /// <param name="prefix"></param>
    /// <returns></returns>
    public Option<string> GetPrefixedAcrValue(string prefix) => GetPrefixedAcrValue(AcrValues, prefix);

    /// <summary>
    ///
    /// </summary>
    /// <param name="acrValues"></param>
    /// <param name="prefix"></param>
    /// <returns></returns>
    public static Option<string> GetPrefixedAcrValue(IEnumerable<string> acrValues, string prefix) => acrValues.TryFirst(v => v.StartsWith(prefix)).Map(v => v[prefix.Length..]);

    /// <summary>
    /// Iterate AuthContext as a sequence of key-value pairs
    /// </summary>
    /// <returns></returns>
    public IEnumerable<(string Key, StringValues Value)> IterateApiParameters() {
        yield return (OidcConstants.AuthorizeRequest.ResponseType, ResponseType.ToString());
        yield return (OidcConstants.AuthorizeRequest.ResponseMode, ResponseMode);
        yield return (OidcConstants.AuthorizeRequest.ClientId, ClientId);
        yield return (OidcConstants.AuthorizeRequest.Scope, Scopes.ToSpaceSeparatedString());
        yield return (OidcConstants.AuthorizeRequest.AcrValues, AcrValues.ToSpaceSeparatedString());
        yield return (OidcConstants.AuthorizeRequest.RedirectUri, RedirectUri);
        yield return (OidcConstants.AuthorizeRequest.MaxAge, MaxAge.ToString());
        if (State.IsSome) yield return (OidcConstants.AuthorizeRequest.State, State.Get());
        if (Pkce.IsSome) {
            yield return (OidcConstants.AuthorizeRequest.CodeChallenge, Pkce.Get().CodeChallenge);
            yield return (OidcConstants.AuthorizeRequest.CodeChallengeMethod, Pkce.Get().CodeChallengeMethod);
        }
        if (Nonce.IsSome) yield return (OidcConstants.AuthorizeRequest.Nonce, Nonce.Get());
        if (LoginHint.IsSome) yield return (OidcConstants.AuthorizeRequest.LoginHint, LoginHint.Get());
        yield return (OidcConstants.AuthorizeRequest.Prompt, PromptModes.ToSpaceSeparatedString());
        if (UiLocales.IsSome) yield return (OidcConstants.AuthorizeRequest.UiLocales, UiLocales.Get());
        if (DisplayMode.IsSome) yield return (OidcConstants.AuthorizeRequest.Display, DisplayMode.Get());
        if (Request.IsSome) yield return (OidcConstants.AuthorizeRequest.Request, Request.Get());
        if (RequestUri.IsSome) yield return (OidcConstants.AuthorizeRequest.RequestUri, RequestUri.Get());
        foreach (var i in AdditionalParameters)
            yield return i;
    }

    /// <summary>
    /// To query string dictionary
    /// </summary>
    /// <returns></returns>
    public ApiParameters ToApiParameters() => IterateApiParameters().ToImmutableDictionary();
}