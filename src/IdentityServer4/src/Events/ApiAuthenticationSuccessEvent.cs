// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;

namespace IdentityServer4.Events;

/// <summary>
/// Event for successful API authentication
/// </summary>
/// <seealso cref="Event" />
public static class ApiAuthenticationSuccessEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ApiAuthenticationSuccessEvent"/> class.
    /// </summary>
    /// <param name="apiName">Name of the API.</param>
    /// <param name="authenticationMethod">The authentication method.</param>
    public static Event Create(string apiName, string authenticationMethod) =>
        new(EventCategories.Authentication,
            "API Authentication Success",
            EventTypes.Success,
            EventIds.ApiAuthenticationSuccess,
            new{
                ApiName = apiName,
                AuthenticationMethod = authenticationMethod
            });
}