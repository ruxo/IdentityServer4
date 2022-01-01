// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Diagnostics;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Models;

/// <summary>
/// Models the common data of API and identity resources.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public abstract class Resource
{
    string DebuggerDisplay => Name;

    /// <summary>
    /// New Resource
    /// </summary>
    protected Resource()
    {
        Name = $"{{{GetType()}}}";
    }

    /// <summary>
    /// Indicates if this resource is enabled. Defaults to true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The unique name of the resource.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Display name of the resource.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Description of the resource.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Specifies whether this scope is shown in the discovery document. Defaults to true.
    /// </summary>
    public bool ShowInDiscoveryDocument { get; set; } = true;

    /// <summary>
    /// List of associated user claims that should be included when this resource is requested.
    /// </summary>
    public string[] UserClaims { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the custom properties for the resource.
    /// </summary>
    /// <value>
    /// The properties.
    /// </value>
    public Dictionary<string, string> Properties { get; set; } = new();
}