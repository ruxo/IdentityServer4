// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using IdentityModel;
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
/// Parses a POST body for a JWT bearer client assertion
/// </summary>
public class JwtBearerClientAssertionSecretParser : ISecretParser
{
    readonly IdentityServerOptions options;
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtBearerClientAssertionSecretParser"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="logger">The logger.</param>
    public JwtBearerClientAssertionSecretParser(IdentityServerOptions options, ILogger<JwtBearerClientAssertionSecretParser> logger)
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
    public string AuthenticationMethod => OidcConstants.EndpointAuthenticationMethods.PrivateKeyJwt;

    /// <summary>
    /// Tries to find a JWT client assertion token in the request body that can be used for authentication
    /// Used for "private_key_jwt" client authentication method as defined in http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    /// </summary>
    /// <param name="context">The HTTP context</param>
    /// <returns>
    /// A parsed secret
    /// </returns>
    public async Task<Option<ParsedSecret>> ParseAsync(HttpContext context)
    {
        logger.LogDebug("Start parsing for JWT client assertion in post body");

        if (!context.Request.HasApplicationFormContentType())
        {
            logger.LogDebug("Content type is not a form");
            return None;
        }

        var body = await context.Request.ReadFormAsync();

        var clientAssertionType = body[OidcConstants.TokenRequest.ClientAssertionType].FirstOrDefault();
        var clientAssertion = body[OidcConstants.TokenRequest.ClientAssertion].FirstOrDefault();

        if (clientAssertion.IsPresent() && clientAssertionType == OidcConstants.ClientAssertionTypes.JwtBearer) {
            if (clientAssertion!.Length > options.InputLengthRestrictions.Jwt) {
                logger.LogError("Client assertion token exceeds maximum length");
                return None;
            }

            var clientId = GetClientIdFromToken(clientAssertion);
            if (!clientId.IsPresent()) {
                return None;
            }

            if (clientId!.Length > options.InputLengthRestrictions.ClientId) {
                logger.LogError("Client ID exceeds maximum length");
                return None;
            }

            var parsedSecret = new ParsedSecret{
                Id         = clientId,
                Credential = clientAssertion,
                Type       = IdentityServerConstants.ParsedSecretTypes.JwtBearer
            };

            return parsedSecret;
        }

        logger.LogDebug("No JWT client assertion found in post body");
        return None;
    }

    string? GetClientIdFromToken(string token)
    {
        try
        {
            var jwt = new JwtSecurityToken(token);
            return jwt.Subject;
        }
        catch (Exception e)
        {
            logger.LogWarning("Could not parse client assertion: {Error}", e);
            return null;
        }
    }
}