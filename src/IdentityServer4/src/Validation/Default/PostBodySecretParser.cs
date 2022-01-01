// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System.Linq;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using Microsoft.AspNetCore.Http;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Parses a POST body for secrets
/// </summary>
public class PostBodySecretParser : ISecretParser
{
    readonly ILogger logger;
    readonly IdentityServerOptions options;

    /// <summary>
    /// Creates the parser with options
    /// </summary>
    /// <param name="options">IdentityServer options</param>
    /// <param name="logger">Logger</param>
    public PostBodySecretParser(IdentityServerOptions options, ILogger<PostBodySecretParser> logger)
    {
        this.logger  = logger;
        this.options = options;
    }

    /// <summary>
    /// Returns the authentication method name that this parser implements
    /// </summary>
    /// <value>
    /// The authentication method.
    /// </value>
    public string AuthenticationMethod => OidcConstants.EndpointAuthenticationMethods.PostBody;

    /// <summary>
    /// Tries to find a secret on the context that can be used for authentication
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>
    /// A parsed secret
    /// </returns>
    public async Task<Option<ParsedSecret>> ParseAsync(HttpContext context)
    {
        logger.LogDebug("Start parsing for secret in post body");

        if (!context.Request.HasApplicationFormContentType())
        {
            logger.LogDebug("Content type is not a form");
            return None;
        }

        var body = await context.Request.ReadFormAsync();

        var id = body["client_id"].FirstOrDefault();
        var secret = body["client_secret"].FirstOrDefault();

        // client id must be present
        if (id.IsPresent()) {
            if (id!.Length > options.InputLengthRestrictions.ClientId) {
                logger.LogError("Client ID exceeds maximum length");
                return None;
            }

            if (secret.IsPresent()) {
                if (secret!.Length > options.InputLengthRestrictions.ClientSecret) {
                    logger.LogError("Client secret exceeds maximum length");
                    return None;
                }

                return new ParsedSecret{
                    Id         = id,
                    Credential = secret,
                    Type       = IdentityServerConstants.ParsedSecretTypes.SharedSecret
                };
            }
            else {
                // client secret is optional
                logger.LogDebug("client id without secret found");

                return new ParsedSecret{
                    Id   = id,
                    Type = IdentityServerConstants.ParsedSecretTypes.NoSecret
                };
            }
        }

        logger.LogDebug("No secret in post body found");
        return None;
    }
}