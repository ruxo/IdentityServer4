// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using static IdentityServer4.Constants;

namespace IdentityServer4.Events;

/// <summary>
/// Event for successful user authentication
/// </summary>
/// <seealso cref="Event" />
public static class UserLoginSuccessEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserLoginSuccessEvent"/> class.
    /// </summary>
    /// <param name="provider">The provider.</param>
    /// <param name="providerUserId">The provider user identifier.</param>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="name">The name.</param>
    /// <param name="interactive">if set to <c>true</c> [interactive].</param>
    /// <param name="clientId">The client id.</param>
    public static Event Create(string provider, string providerUserId, string subjectId, string name, bool interactive = true, string? clientId = null) =>
        Create(new{
            Provider = provider,
            ProviderUserId = providerUserId,
            SubjectId = subjectId,
            DisplayName = name,
            EndPoint = interactive ? "UI" : EndpointNames.Token,
            ClientId = clientId
        });

    /// <summary>
    /// Initializes a new instance of the <see cref="UserLoginSuccessEvent"/> class.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="name">The name.</param>
    /// <param name="interactive">if set to <c>true</c> [interactive].</param>
    /// <param name="clientId">The client id.</param>
    public static Event Create(string username, string subjectId, string? name = null, bool interactive = true, string? clientId = null) =>
        Create(new{
            Username = username,
            SubjectId = subjectId,
            DisplayName = name,
            EndPoint = interactive ? "UI" : EndpointNames.Token,
            ClientId = clientId
        });

    /// <summary>
    /// Initializes a new instance of the <see cref="UserLoginSuccessEvent"/> class.
    /// </summary>
    static Event Create(object data) =>
        new(EventCategories.Authentication,
            "User Login Success",
            EventTypes.Success,
            EventIds.UserLoginSuccess,
            data);
}