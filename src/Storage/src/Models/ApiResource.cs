// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace IdentityServer4.Models;

/// <summary>
/// Models a web API resource.
/// </summary>
[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public class ApiResource : Resource
{
    string DebuggerDisplay => Name;

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiResource"/> class.
    /// </summary>
    public ApiResource()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiResource"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    public ApiResource(string name)
        : this(name, name, Array.Empty<string>())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiResource"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="displayName">The display name.</param>
    public ApiResource(string name, string displayName)
        : this(name, displayName, Array.Empty<string>())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiResource"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="userClaims">List of associated user claims that should be included when this resource is requested.</param>
    public ApiResource(string name, IEnumerable<string> userClaims)
        : this(name, name, userClaims)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiResource"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="displayName">The display name.</param>
    /// <param name="userClaims">List of associated user claims that should be included when this resource is requested.</param>
    /// <exception cref="System.ArgumentNullException">name</exception>
    public ApiResource(string name, string displayName, IEnumerable<string> userClaims)
    {
        if (name.IsMissing()) throw new ArgumentNullException(nameof(name));

        Name        = name;
        DisplayName = displayName;
        UserClaims  = userClaims.ToArray();
    }

    #endregion

    /// <summary>
    /// The API secret is used for the introspection endpoint. The API can authenticate with introspection using the API name and secret.
    /// </summary>
    public Secret[] ApiSecrets { get; set; } = Array.Empty<Secret>();

    /// <summary>
    /// Models the scopes this API resource allows.
    /// </summary>
    public string[] Scopes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Signing algorithm for access token. If empty, will use the server default signing algorithm.
    /// </summary>
    public string[] AllowedAccessTokenSigningAlgorithms { get; set; } =Array.Empty<string>();
}