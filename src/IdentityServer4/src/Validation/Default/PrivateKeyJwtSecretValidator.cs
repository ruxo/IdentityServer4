// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using LanguageExt.UnitsOfMeasure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates a secret based on RS256 signed JWT token
/// </summary>
public class PrivateKeyJwtSecretValidator : ISecretValidator
{
    readonly IHttpContextAccessor contextAccessor;
    readonly IReplayCache replayCache;
    readonly ILogger logger;

    static readonly TimeSpan CacheExpiration = 5.Minutes();

    const string Purpose = nameof(PrivateKeyJwtSecretValidator);

    /// <summary>
    /// Instantiates an instance of private_key_jwt secret validator
    /// </summary>
    public PrivateKeyJwtSecretValidator(IHttpContextAccessor contextAccessor, IReplayCache replayCache, ILogger<PrivateKeyJwtSecretValidator> logger)
    {
        this.contextAccessor = contextAccessor;
        this.replayCache = replayCache;
        this.logger = logger;
    }

    /// <summary>
    /// Validates a secret
    /// </summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="credentials">The received secret.</param>
    /// <returns>
    /// A validation result
    /// </returns>
    /// <exception cref="System.ArgumentException">ParsedSecret.Credential is not a JWT token</exception>
    public async ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials)
    {
        if (credentials is not Credentials.JwtBearer(_, var credential))
            return None;

        List<SecurityKey> trustedKeys;
        try
        {
            trustedKeys = await secrets.GetKeysAsync();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Could not parse secrets");
            return None;
        }

        if (!trustedKeys.Any())
        {
            logger.LogError("There are no keys available to validate client assertion");
            return None;
        }

        var validAudiences = new[]
        {
            // issuer URI (tbd)
            //_contextAccessor.HttpContext.GetIdentityServerIssuerUri(),

            // token endpoint URL
            string.Concat(contextAccessor.HttpContext!.GetIdentityServerIssuerUri().EnsureTrailingSlash(), Constants.ProtocolRoutePaths.Token)
        };

        var tokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = trustedKeys,
            ValidateIssuerSigningKey = true,

            ValidIssuer = credentials.ClientId,
            ValidateIssuer = true,

            ValidAudiences = validAudiences,
            ValidateAudience = true,

            RequireSignedTokens = true,
            RequireExpirationTime = true,

            ClockSkew = TimeSpan.FromMinutes(5)
        };
        try
        {
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(credential, tokenValidationParameters, out var token);

            var jwtToken = (JwtSecurityToken)token;
            if (jwtToken.Subject != jwtToken.Issuer)
            {
                logger.LogError("Both 'sub' and 'iss' in the client assertion token must have a value of client_id");
                return None;
            }

            var exp = jwtToken.Payload.Exp;
            if (!exp.HasValue)
            {
                logger.LogError("exp is missing");
                return None;
            }

            var jti = jwtToken.Payload.Jti;
            if (jti.IsMissing())
            {
                logger.LogError("jti is missing");
                return None;
            }

            if (await replayCache.ExistsAsync(Purpose, jti))
            {
                logger.LogError("jti is found in replay cache. Possible replay attack");
                return None;
            }
            else
            {
                await replayCache.AddAsync(Purpose, jti, DateTimeOffset.FromUnixTimeSeconds(exp.Value) + CacheExpiration);
            }
            return new SecretInfo();
        }
        catch (Exception e)
        {
            logger.LogError(e, "JWT token validation error");
            return None;
        }
    }
}