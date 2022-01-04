// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Configuration.DependencyInjection.Options;

/// <summary>
/// The ValidationOptions contains settings that affect some of the default validation behavior.
/// </summary>
public class ValidationOptions
{
    /// <summary>
    ///  Collection of URI scheme prefixes that should never be used as custom URI schemes in the redirect_uri passed to tha authorize endpoint.
    /// </summary>
    public string[] InvalidRedirectUriPrefixes { get; } = {
        "javascript:",
        "file:",
        "data:",
        "mailto:",
        "ftp:",
        "blob:",
        "about:",
        "ssh:",
        "tel:",
        "view-source:",
        "ws:",
        "wss:"
    };
}