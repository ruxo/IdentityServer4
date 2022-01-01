// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using LanguageExt;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.ResponseHandling;

/// <summary>
/// Indicates interaction outcome for user on authorization endpoint.
/// </summary>
public class InteractionResponse
{
    /// <summary>
    /// Gets or sets a value indicating whether the user must login.
    /// </summary>
    /// <value>
    ///   <c>true</c> if this instance is login; otherwise, <c>false</c>.
    /// </value>
    public bool IsLogin { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user must consent.
    /// </summary>
    /// <value>
    /// <c>true</c> if this instance is consent; otherwise, <c>false</c>.
    /// </value>
    public bool IsConsent { get; set; }

    /// <summary>
    /// Gets a value indicating whether the result is an error.
    /// </summary>
    /// <value>
    ///   <c>true</c> if this instance is error; otherwise, <c>false</c>.
    /// </value>
    public bool IsError => Error.IsSome;

    /// <summary>
    /// Gets or sets the error.
    /// </summary>
    /// <value>
    /// The error.
    /// </value>
    public Option<string> Error { get; set; } = None;

    /// <summary>
    /// Gets or sets the error description.
    /// </summary>
    /// <value>
    /// The error description.
    /// </value>
    public Option<string> ErrorDescription { get; set; } = None;

    /// <summary>
    /// Gets a value indicating whether the user must be redirected to a custom page.
    /// </summary>
    /// <value>
    /// <c>true</c> if this instance is redirect; otherwise, <c>false</c>.
    /// </value>
    public bool IsRedirect => RedirectUrl.Bind(url => url.AsPresent()).IsSome;

    /// <summary>
    /// Gets or sets the URL for the custom page.
    /// </summary>
    /// <value>
    /// The redirect URL.
    /// </value>
    public Option<string> RedirectUrl { get; set; }
}