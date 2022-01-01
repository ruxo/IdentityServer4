// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Security.Claims;

namespace IdentityServer4.Models;

/// <summary>
/// Represents data needed for device flow.
/// </summary>
/// <param name="ClientId">the client identifier</param>
/// <param name="Description">the description the user assigned to the device being authorized.</param>
/// <param name="IsOpenId">a value indicating whether this instance is open identifier.</param>
// ReSharper disable once NotAccessedPositionalProperty.Global
public sealed record DeviceCode(string Code, string ClientId, string Description, bool IsOpenId, int Lifetime, DateTime CreationTime, string[] RequestedScopes) : IAuthorizationModel
{
    /// <summary>
    /// Gets or sets a value indicating whether this instance is authorized.
    /// </summary>
    /// <value>
    ///   <c>true</c> if this instance is authorized; otherwise, <c>false</c>.
    /// </value>
    public bool IsAuthorized { get; set; }

    /// <summary>
    /// Gets or sets the authorized scopes.
    /// </summary>
    /// <value>
    /// The authorized scopes.
    /// </value>
    public string[] AuthorizedScopes { get; set; } = Array.Empty<string>();

    /// <inheritdoc />
    public string[] Scopes => AuthorizedScopes;

    /// <inheritdoc />
    public Option<ClaimsPrincipal> Subject { get; set; }

    /// <summary>
    /// Gets or sets the session identifier.
    /// </summary>
    /// <value>
    /// The session identifier.
    /// </value>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Description after consent is granted.
    /// </summary>
    public string ConsentDescription { get; set; } = string.Empty;
}