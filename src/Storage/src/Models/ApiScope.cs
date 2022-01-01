// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Diagnostics;
using System.Linq;

namespace IdentityServer4.Models;

/// <summary>
/// Models access to an API scope
/// </summary>
[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public class ApiScope : Resource
{
    string DebuggerDisplay => Name;

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiScope"/> class.
    /// </summary>
    public ApiScope()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiScope"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    public ApiScope(string name)
        : this(name, name, Array.Empty<string>())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiScope"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="displayName">The display name.</param>
    public ApiScope(string name, string displayName)
        : this(name, displayName, Array.Empty<string>())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiScope"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="userClaims">List of associated user claims that should be included when this resource is requested.</param>
    public ApiScope(string name, IEnumerable<string> userClaims)
        : this(name, name, userClaims)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiScope"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="displayName">The display name.</param>
    /// <param name="userClaims">List of associated user claims that should be included when this resource is requested.</param>
    /// <exception cref="System.ArgumentNullException">name</exception>
    public ApiScope(string name, string displayName, IEnumerable<string> userClaims)
    {
        Name = name;
        DisplayName = displayName;
        UserClaims = UserClaims.Concat(userClaims).ToArray();
    }

    #endregion

    /// <summary>
    /// Specifies whether the user can de-select the scope on the consent screen. Defaults to false.
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// Specifies whether the consent screen will emphasize this scope. Use this setting for sensitive or important scopes. Defaults to false.
    /// </summary>
    public bool Emphasize { get; set; }
}