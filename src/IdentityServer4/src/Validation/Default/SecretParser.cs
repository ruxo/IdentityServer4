// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Uses the registered secret parsers to parse a secret on the current request
/// </summary>
public class SecretParser : ISecretsListParser
{
    readonly ILogger logger;
    readonly IEnumerable<ISecretParser> parsers;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretParser"/> class.
    /// </summary>
    /// <param name="parsers">The parsers.</param>
    /// <param name="logger">The logger.</param>
    public SecretParser(IEnumerable<ISecretParser> parsers, ILogger<SecretParser> logger)
    {
        this.parsers = parsers;
        this.logger  = logger;
    }

    /// <summary>
    /// Checks the context to find a secret.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns></returns>
    public async Task<Option<ParsedSecret>> ParseAsync(HttpContext context)
    {
        bool notNoSecret(ISecretParser parser, ParsedSecret parsedSecret) {
            logger.LogDebug("Parser found secret: {Type}", parser.GetType().Name);
            return parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.NoSecret;
        }

        // see if a registered parser finds a secret on the request
        var bestSecret = await parsers.ChooseAsync(parser => parser.ParseAsync(context).Map(secret => (parser, secret)))
                                      .TryFirst(i => notNoSecret(i.parser, i.secret))
                                      .Map(i => i.secret);

        if (bestSecret.IsSome)
            logger.LogDebug("Secret id found: {Id}", bestSecret.Get(s => s.Id));
        else
            logger.LogDebug("Parser found no secret");
        return bestSecret;
    }

    /// <summary>
    /// Gets all available authentication methods.
    /// </summary>
    /// <returns></returns>
    public IEnumerable<string> GetAvailableAuthenticationMethods()
    {
        return parsers.Select(p => p.AuthenticationMethod).Where(p => !String.IsNullOrWhiteSpace(p));
    }
}