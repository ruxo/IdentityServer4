// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;

namespace IdentityServer4.Events;

/// <summary>
/// Event for failed API authentication
/// </summary>
/// <seealso cref="Event" />
public static class ApiAuthenticationFailureEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ApiAuthenticationFailureEvent"/> class.
    /// </summary>
    /// <param name="apiName">Name of the API.</param>
    /// <param name="message">The message.</param>
    public static Event Create(string apiName, string message) =>
        new(EventCategories.Authentication,
            "API Authentication Failure",
            EventTypes.Failure,
            EventIds.ApiAuthenticationFailure,
            new{
                ApiName = apiName,
                Message = message
            });
}