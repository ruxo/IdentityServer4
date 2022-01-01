// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using RZ.Foundation.Extensions;

namespace IdentityServer4.Models;

/// <summary>
/// Models a collection of identity and API resources.
/// </summary>
public class Resources
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Resources"/> class.
    /// </summary>
    Resources()
    {
    }
/*
    /// <summary>
    /// Initializes a new instance of the <see cref="Resources"/> class.
    /// </summary>
    /// <param name="other">The other.</param>
    public Resources(Resources other)
        : this(other.IdentityResources, other.ApiResources, other.ApiScopes)
    {
        OfflineAccess = other.OfflineAccess;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Resources"/> class.
    /// </summary>
    /// <param name="identityResources">The identity resources.</param>
    /// <param name="apiResources">The API resources.</param>
    /// <param name="apiScopes">The API scopes.</param>
    public Resources(IEnumerable<IdentityResource> identityResources, IEnumerable<ApiResource> apiResources, IEnumerable<ApiScope> apiScopes)
    {
        IdentityResources = identityResources.AsArray();
        ApiResources      = apiResources.AsArray();
        ApiScopes         = apiScopes.AsArray();
    }

    /// <summary>
    /// Gets or sets a value indicating whether [offline access].
    /// </summary>
    /// <value>
    ///   <c>true</c> if [offline access]; otherwise, <c>false</c>.
    /// </value>
    public bool OfflineAccess { get; set; }

    /// <summary>
    /// Gets or sets the identity resources.
    /// </summary>
    public IdentityResource[] IdentityResources { get; set; } = Array.Empty<IdentityResource>();

    /// <summary>
    /// Gets or sets the API resources.
    /// </summary>
    public ApiResource[] ApiResources { get; set; } = Array.Empty<ApiResource>();

    /// <summary>
    /// Gets or sets the API scopes.
    /// </summary>
    public ApiScope[] ApiScopes { get; set; } = Array.Empty<ApiScope>();
    */
}