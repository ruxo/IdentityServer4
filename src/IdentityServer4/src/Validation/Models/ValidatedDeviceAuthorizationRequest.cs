// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Validation.Models;

/// <summary>
/// Models a validated request to the device authorization endpoint.
/// </summary>
public class ValidatedDeviceAuthorizationRequest : ValidatedRequest
{
    /// <summary>
    /// Gets or sets the requested scopes.
    /// </summary>
    /// <value>
    /// The scopes.
    /// </value>
    public string[] RequestedScopes { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this instance is open identifier request.
    /// </summary>
    /// <value>
    ///   <c>true</c> if this instance is open identifier request; otherwise, <c>false</c>.
    /// </value>
    public bool IsOpenIdRequest { get; set; }

    /// <summary>
    /// Gets the description the user assigned to the device being authorized.
    /// </summary>
    /// <value>
    /// The description.
    /// </value>
    public string Description { get; set; }
}