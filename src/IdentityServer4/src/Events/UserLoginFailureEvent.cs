// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using static IdentityServer4.Constants;

namespace IdentityServer4.Events;

/// <summary>
/// Event for failed user authentication
/// </summary>
/// <seealso cref="Event" />
public static class UserLoginFailureEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="T:IdentityServer4.Events.UserLoginFailureEvent" /> class.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="error">The error.</param>
    /// <param name="interactive">Specifies if login was interactive</param>
    /// <param name="clientId">The client id</param>
    public static Event Create(string username, string error, bool interactive = true, string? clientId = null) =>
        new(EventCategories.Authentication,
            "User Login Failure",
            EventTypes.Failure,
            EventIds.UserLoginFailure,
            new{
                Username = username,
                ClientId = clientId,
                EndPoint = interactive ? "UI" : EndpointNames.Token
            });
}