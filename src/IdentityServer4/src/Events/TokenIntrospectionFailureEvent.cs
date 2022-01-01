// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Events.Infrastructure;

namespace IdentityServer4.Events;

/// <summary>
/// Event for failed token introspection
/// </summary>
/// <seealso cref="Event" />
public static class TokenIntrospectionFailureEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIntrospectionSuccessEvent" /> class.
    /// </summary>
    /// <param name="apiName">Name of the API.</param>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="token">The token.</param>
    /// <param name="apiScopes">The API scopes.</param>
    /// <param name="tokenScopes">The token scopes.</param>
    public static Event Create(string apiName, string errorMessage, string? token = null, string[]? apiScopes = null, string[]? tokenScopes = null) =>
        new(EventCategories.Token,
            "Token Introspection Failure",
            EventTypes.Failure,
            EventIds.TokenIntrospectionFailure,
            new{
                Message = errorMessage,
                ApiName = apiName,
                Token = token.IsPresent() ? token!.Obfuscate() : null,
                ApiScopes = apiScopes,
                TokenScopes = tokenScopes
            });
}