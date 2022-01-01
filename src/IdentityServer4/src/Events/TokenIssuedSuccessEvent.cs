// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Validation;
using IdentityServer4.Events.Infrastructure;
using IdentityServer4.ResponseHandling.Models;
using static IdentityServer4.Constants;
// ReSharper disable NotAccessedPositionalProperty.Global

namespace IdentityServer4.Events;

/// <summary>
/// Event for successful token issuance
/// </summary>
/// <seealso cref="Event" />
public static class TokenIssuedSuccessEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIssuedSuccessEvent"/> class.
    /// </summary>
    /// <param name="response">The response.</param>
    public static Event Create(AuthorizeResponse response) =>
        new(EventCategories.Token,
            "Token Issued Success",
            EventTypes.Success,
            EventIds.TokenIssuedSuccess,
            new{
                ClientId = response.Request.ValidatedClient.GetOrDefault(c => c.ClientId),
                ClientName = response.Request.ValidatedClient.GetOrDefault(c => c.Client.ClientName),
                RedirectUri = response.RedirectUri,
                Endpoint = EndpointNames.Authorize,
                SubjectId = response.Request.Subject.GetSubjectId(),
                Scopes = response.Scope,
                GrantType = response.Request.GrantType,
                Tokens = GetTokens(response).ToArray()
            });

    static IEnumerable<Token> GetTokens(AuthorizeResponse response) {
        if (response.IdentityToken.IsSome) yield return Token.Create(OidcConstants.TokenTypes.IdentityToken, response.IdentityToken.Get());
        if (response.Code.IsSome) yield return Token.Create(OidcConstants.ResponseTypes.Code, response.Code.Get());
        if (response.AccessToken.IsSome) yield return Token.Create(OidcConstants.TokenTypes.AccessToken, response.AccessToken.Get());
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIssuedSuccessEvent"/> class.
    /// </summary>
    /// <param name="response">The response.</param>
    /// <param name="request">The request.</param>
    public static Event Create(TokenResponse response, TokenRequestValidationResult request) =>
        new(EventCategories.Token,
            "Token Issued Success",
            EventTypes.Success,
            EventIds.TokenIssuedSuccess,
            new{
                ClientId = request.ValidatedRequest.ValidatedClient.GetOrDefault(c => c.ClientId),
                ClientName = request.ValidatedRequest.ValidatedClient.GetOrDefault(c => c.Client.ClientName),
                Endpoint = EndpointNames.Token,
                SubjectId = request.ValidatedRequest.Subject.GetSubjectId(),
                GrantType = request.ValidatedRequest.GrantType,
                Scopes = request.ValidatedRequest.GrantType switch {
                    OidcConstants.GrantTypes.RefreshToken      => request.ValidatedRequest.RefreshToken.AccessToken.Scopes.ToSpaceSeparatedString(),
                    OidcConstants.GrantTypes.AuthorizationCode => request.ValidatedRequest.AuthorizationCode.Get().RequestedScopes.ToSpaceSeparatedString(),
                    _                                          => request.ValidatedRequest.ValidatedResources.RawScopeValues.ToSpaceSeparatedString()
                },
                Tokens = GetTokens(response).ToArray()
            });

    static IEnumerable<Token> GetTokens(TokenResponse response) {
        if (response.IdentityToken.IsSome) yield return Token.Create(OidcConstants.TokenTypes.IdentityToken, response.IdentityToken.Get());
        if (response.RefreshToken.IsSome) yield return Token.Create(OidcConstants.ResponseTypes.Code, response.RefreshToken.Get());
        yield return Token.Create(OidcConstants.TokenTypes.AccessToken, response.AccessToken);
    }

    /// <summary>
    /// Data structure serializing issued tokens
    /// </summary>
    public sealed record Token(string TokenType, string TokenValue)
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Token"/> class.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        public static Token Create(string type, string value) =>
            new(type, value.Obfuscate());
    }
}