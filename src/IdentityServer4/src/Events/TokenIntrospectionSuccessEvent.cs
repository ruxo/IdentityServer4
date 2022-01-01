// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using System.Linq;
using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Events;

/// <summary>
/// Event for successful token introspection
/// </summary>
/// <seealso cref="Event" />
public static class TokenIntrospectionSuccessEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIntrospectionSuccessEvent" /> class.
    /// </summary>
    public static Event Create(string apiName, TokenValidationResult result) =>
        new(EventCategories.Token,
            "Token Introspection Success",
            EventTypes.Success,
            EventIds.TokenIntrospectionSuccess,
            new{
                ApiName = apiName,
                Token = result.Token.AsPresent().Map(s => s.Obfuscate()).GetOrDefault(),
                ClaimTypes = result.Claims.Select(c => c.Type).Distinct().ToArray(),
                TokenScopes = result.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ToArray()
            });
}