// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServer4.Models;

namespace IdentityServer4.Services;

/// <summary>
/// Logic for creating security tokens
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Creates an identity token.
    /// </summary>
    /// <param name="request">The token creation request.</param>
    /// <returns>An identity token</returns>
    Task<Token> CreateIdentityTokenAsync(TokenCreationRequest request);

    /// <summary>
    /// Creates an access token.
    /// </summary>
    /// <param name="request">The token creation request.</param>
    /// <returns>An access token</returns>
    [Obsolete]
    Task<Token> CreateAccessTokenAsync(TokenCreationRequest request);

    /// <summary>
    /// Creates an access token.
    /// </summary>
    Task<Token> CreateAccessTokenAsync(AuthenticatedUser user, Option<string> sessionId, Client client, ImmutableHashSet<string> scopes,
                                       Resource[] resources, Option<string> confirmation, Option<string> description);

    /// <summary>
    /// Creates an access token.
    /// </summary>
    Task<Token> CreateAccessTokenAsync(AuthenticatedUser user, Option<string> sessionId, Client client, ImmutableHashSet<string> scopes,
                                       Resource[] resources, Option<string> confirmation, string? description = null) =>
        CreateAccessTokenAsync(user, sessionId, client, scopes, resources, confirmation, Optional(description!));

    /// <summary>
    /// Creates a serialized and protected security token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <returns>A security token in serialized form</returns>
    Task<string> CreateSecurityTokenAsync(Token token);
}