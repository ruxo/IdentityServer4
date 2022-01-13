// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates JWT authorization request objects
/// </summary>
public sealed class JwtRequestValidator
{
    readonly IHttpContextAccessor httpContextAccessor;

    /// <summary>
    /// JWT handler
    /// </summary>
    readonly JwtSecurityTokenHandler handler = new(){ MapInboundClaims = false };

    /// <summary>
    /// The audience URI to use
    /// </summary>
    string AudienceUri => httpContextAccessor.HttpContext!.GetIdentityServerIssuerUri();

    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// The option
    /// </summary>
    readonly IdentityServerOptions options;

    /// <summary>
    /// Instantiates an instance of private_key_jwt secret validator
    /// </summary>
    public JwtRequestValidator(IHttpContextAccessor contextAccessor, IdentityServerOptions options, ILogger<JwtRequestValidator> logger)
    {
        httpContextAccessor = contextAccessor;

        this.options = options;
        this.logger = logger;
    }

    /// <summary>
    /// Validates a JWT request object
    /// </summary>
    /// <param name="client">The client</param>
    /// <param name="jwtTokenString">The JWT</param>
    /// <returns></returns>
    public async Task<ImmutableDictionary<string,string>> GetTokenRawClaim(Client client, string jwtTokenString)
    {
        var trustedKeys = await client.ClientSecrets.GetKeysAsync();

        if (!trustedKeys.Any())
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "There are no keys available to validate JWT");

        var jwtSecurityToken = ValidateJwtAsync(jwtTokenString, trustedKeys, client);

        if (jwtSecurityToken.Payload.ContainsKey(OidcConstants.AuthorizeRequest.Request) ||
            jwtSecurityToken.Payload.ContainsKey(OidcConstants.AuthorizeRequest.RequestUri))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "JWT payload must not contain request or request_uri");

        return PayloadToDict(jwtSecurityToken);
    }

    /// <summary>
    /// Validates the JWT token
    /// </summary>
    /// <param name="jwtTokenString">JWT as a string</param>
    /// <param name="keys">The keys</param>
    /// <param name="client">The client</param>
    /// <returns></returns>
    JwtSecurityToken ValidateJwtAsync(string jwtTokenString, IEnumerable<SecurityKey> keys, Client client)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = keys,
            ValidateIssuerSigningKey = true,

            ValidIssuer = client.ClientId,
            ValidateIssuer = true,

            ValidAudience = AudienceUri,
            ValidateAudience = true,

            RequireSignedTokens = true,
            RequireExpirationTime = true,

            ValidTypes = options.StrictJarValidation? new[]{ JwtClaimTypes.JwtTypes.AuthorizationRequest } : Enumerable.Empty<string>()
        };
        handler.ValidateToken(jwtTokenString, tokenValidationParameters, out var token);

        return (JwtSecurityToken)token;
    }

    /// <summary>
    /// Processes the JWT contents
    /// </summary>
    /// <param name="token">The JWT token</param>
    /// <returns></returns>
    ImmutableDictionary<string, string> PayloadToDict(JwtSecurityToken token) {
        return (from item in token.Payload
                where !Constants.Filters.JwtRequestClaimTypesFilter.Contains(item.Key)
                select itemize(item.Key)).ToImmutableDictionary();

        // local function
        (string, string) itemize(string key) {
            var value = token.Payload[key];
            switch (value) {
                case string s:
                    return (key, s);
                case JObject jobj:
                    return (key, jobj.ToString(Formatting.None));
                case JArray jarr:
                    return (key, jarr.ToString(Formatting.None));
                default:
                    logger.LogWarning("Detect invalid JWT payload key={Key}, value={Value}", key, value);
                    return (key, value?.ToString() ?? string.Empty);
            }
        }
    }
}