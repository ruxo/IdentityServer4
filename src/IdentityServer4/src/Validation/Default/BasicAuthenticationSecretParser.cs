// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using System;
using System.Text;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using Microsoft.AspNetCore.Http;

#pragma warning disable CS1998

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Parses a Basic Authentication header
/// </summary>
public sealed class BasicAuthenticationSecretParser : ISecretParser
{
    readonly ILogger logger;
    readonly IdentityServerOptions options;

    /// <summary>
    /// Creates the parser with a reference to identity server options
    /// </summary>
    /// <param name="options">IdentityServer options</param>
    /// <param name="logger">The logger</param>
    public BasicAuthenticationSecretParser(IdentityServerOptions options, ILogger<BasicAuthenticationSecretParser> logger)
    {
        this.options = options;
        this.logger  = logger;
    }

    /// <summary>
    /// Returns the authentication method name that this parser implements
    /// </summary>
    /// <value>
    /// The authentication method.
    /// </value>
    public string AuthenticationMethod => OidcConstants.EndpointAuthenticationMethods.BasicAuthentication;

    /// <summary>
    /// Tries to find a secret that can be used for authentication
    /// </summary>
    /// <returns>
    /// A parsed secret
    /// </returns>
    public async Task<Option<ParsedSecret>> ParseAsync(HttpContext context)
    {
        logger.LogDebug("Start parsing Basic Authentication secret");

        var authorizationHeader = context.Request.Headers.Get("Authorization").Bind(a => a.TryFirst()).IfNone(string.Empty);

        if (authorizationHeader.IsMissing() || !authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
            logger.LogError("No Authorization header found");
            return None;
        }

        var parameter = authorizationHeader.Substring("Basic ".Length);

        string pair;
        try
        {
            pair = Encoding.UTF8.GetString(Convert.FromBase64String(parameter));
        }
        catch (Exception e)
        {
            if (e is FormatException or ArgumentException) {
                logger.LogWarning("Malformed Basic Authentication credential");
                return None;
            }
            throw;
        }

        var ix = pair.IndexOf(':');
        if (ix == -1)
        {
            logger.LogWarning("Malformed Basic Authentication credential");
            return None;
        }

        var clientId = pair.Substring(0, ix);
        var secret = pair.Substring(ix + 1);

        if (clientId.IsPresent())
        {
            if (clientId.Length > options.InputLengthRestrictions.ClientId)
            {
                logger.LogError("Client ID exceeds maximum length");
                return None;
            }

            if (secret.IsPresent())
            {
                if (secret.Length > options.InputLengthRestrictions.ClientSecret)
                {
                    logger.LogError("Client secret exceeds maximum length");
                    return None;
                }

                return new ParsedSecret(IdentityServerConstants.ParsedSecretTypes.SharedSecret, Decode(clientId), Decode(secret));
            }
            else
            {
                // client secret is optional
                logger.LogDebug("client id without secret found");

                return new ParsedSecret(IdentityServerConstants.ParsedSecretTypes.NoSecret, Decode(clientId), None);
            }
        }

        logger.LogDebug("No Basic Authentication secret found");
        return None;
    }

    // RFC6749 says individual values must be application/x-www-form-urlencoded
    // 2.3.1
    static string Decode(string value)
    {
        if (value.IsMissing()) return string.Empty;

        return Uri.UnescapeDataString(value.Replace("+", "%20"));
    }
}