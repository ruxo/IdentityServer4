// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Configuration;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using LanguageExt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Parses secret according to MTLS spec
/// </summary>
public class MutualTlsSecretParser : ISecretParser
{
    readonly IdentityServerOptions options;
    readonly ILogger<MutualTlsSecretParser> logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="options"></param>
    /// <param name="logger"></param>
    public MutualTlsSecretParser(IdentityServerOptions options, ILogger<MutualTlsSecretParser> logger)
    {
        this.options = options;
        this.logger  = logger;
    }

    /// <summary>
    /// Name of authentication method (blank to suppress in discovery since we do special handling)
    /// </summary>
    public string AuthenticationMethod => String.Empty;

    /// <summary>
    /// Parses the HTTP context
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async Task<Option<ParsedSecret>> ParseAsync(HttpContext context)
    {
        logger.LogDebug("Start parsing for client id in post body");

        if (!context.Request.HasApplicationFormContentType())
        {
            logger.LogDebug("Content type is not a form");
            return None;
        }

        var body = await context.Request.ReadFormAsync();

        var id = body["client_id"].FirstOrDefault();

        // client id must be present
        if (!String.IsNullOrWhiteSpace(id)) {
            if (id.Length > options.InputLengthRestrictions.ClientId) {
                logger.LogError("Client ID exceeds maximum length");
                return None;
            }

            var clientCertificate = await context.Connection.GetClientCertificateAsync();

            if (clientCertificate is null) {
                logger.LogDebug("Client certificate not present");
                return None;
            }

            return new ParsedSecret{
                Id         = id,
                Credential = clientCertificate,
                Type       = IdentityServerConstants.ParsedSecretTypes.X509Certificate
            };
        }

        logger.LogDebug("No post body found");
        return None;
    }
}