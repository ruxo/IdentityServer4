// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using static IdentityServer4.IdentityServerConstants;
#pragma warning disable CS1998

namespace IdentityServer4.Services.Default;

/// <summary>
/// Default token creation service
/// </summary>
public sealed class DefaultTokenCreationService : ITokenCreationService
{
    /// <summary>
    /// The key service
    /// </summary>
    readonly IKeyMaterialService keys;

    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    ///  The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// The options
    /// </summary>
    readonly IdentityServerOptions options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTokenCreationService"/> class.
    /// </summary>
    /// <param name="clock">The options.</param>
    /// <param name="keys">The keys.</param>
    /// <param name="options">The options.</param>
    /// <param name="logger">The logger.</param>
    public DefaultTokenCreationService(
        ISystemClock clock,
        IKeyMaterialService keys,
        IdentityServerOptions options,
        ILogger<DefaultTokenCreationService> logger)
    {
        this.clock = clock;
        this.keys = keys;
        this.options = options;
        this.logger = logger;
    }

    /// <inheritdoc />
    public async Task<string> CreateTokenAsync(string tokenType, IEnumerable<string> allowedSigningAlgorithms, string issuer, int lifetime, string[] audiences, Claim[] claims,
                                               Option<string> confirmation) {
        var header = await CreateHeaderAsync(tokenType, allowedSigningAlgorithms);
        var payload = await CreateJwtPayload(issuer, lifetime, audiences, claims, confirmation);

        return await CreateJwtAsync(new JwtSecurityToken(header, payload));
    }

    async Task<JwtHeader> CreateHeaderAsync(string tokenType, IEnumerable<string> allowedSigningAlgorithms)
    {
        var credential = await keys.GetSigningCredentialsAsync(allowedSigningAlgorithms);

        var header = new JwtHeader(credential);

        // emit x5t claim for backwards compatibility with v4 of MS JWT library
        if (credential.Key is X509SecurityKey x509Key)
        {
            var cert = x509Key.Certificate;
            if (clock.UtcNow.UtcDateTime > cert.NotAfter)
            {
                logger.LogWarning("Certificate {SubjectName} has expired on {Expiration}", cert.Subject, cert.NotAfter.ToString(CultureInfo.InvariantCulture));
            }

            header["x5t"] = Base64Url.Encode(cert.GetCertHash());
        }

        if (tokenType == TokenTypes.AccessToken && options.AccessTokenJwtType.IsPresent())
            header["typ"] = options.AccessTokenJwtType;

        return header;
    }

    async Task<JwtPayload> CreateJwtPayload(string issuer, int lifetime, IEnumerable<string> audiences, Claim[] claims, Option<string> confirmation) {
            var payload = new JwtPayload(
                issuer,
                null,
                null,
                clock.UtcNow.UtcDateTime,
                clock.UtcNow.UtcDateTime.AddSeconds(lifetime));

            foreach (var aud in audiences) payload.AddClaim(new(JwtClaimTypes.Audience, aud));

            var amrClaims = claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
            var scopeClaims = claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
            var jsonClaims = claims.Where(x => x.ValueType == IdentityServerConstants.ClaimValueTypes.Json).ToList();

            // add confirmation claim if present (it's JSON valued)
            confirmation.Do(c => jsonClaims.Add(new(JwtClaimTypes.Confirmation, c, IdentityServerConstants.ClaimValueTypes.Json)));

            var normalClaims = claims.Except(amrClaims).Except(jsonClaims).Except(scopeClaims);

            payload.AddClaims(normalClaims);

            // scope claims
            if (scopeClaims.Any())
            {
                var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                    payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                else
                    payload.Add(JwtClaimTypes.Scope, scopeValues);
            }

            // amr claims
            if (amrClaims.Any())
            {
                var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
            }

            // deal with json types
            // calling ToArray() to trigger JSON parsing once and so later
            // collection identity comparisons work for the anonymous type
            var jsonTokens = jsonClaims.Select(x => new{ x.Type, JsonValue = JToken.Parse(x.Value) }).ToArray();

            var jsonObjects = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Object).ToArray();
            var jsonObjectGroups = jsonObjects.GroupBy(x => x.Type).ToArray();
            foreach (var group in jsonObjectGroups) {
                if (payload.ContainsKey(group.Key))
                    throw new($"Can't add two claims where one is a JSON object and the other is not a JSON object ({group.Key})");

                if (group.Skip(1).Any())
                    payload.Add(group.Key, group.Select(x => x.JsonValue).ToArray());
                else
                    payload.Add(group.Key, group.First().JsonValue);
            }

            var jsonArrays = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Array).ToArray();
            var jsonArrayGroups = jsonArrays.GroupBy(x => x.Type).ToArray();
            foreach (var group in jsonArrayGroups) {
                if (payload.ContainsKey(group.Key))
                    throw new($"Can't add two claims where one is a JSON array and the other is not a JSON array ({group.Key})");

                var newArr = new List<JToken>();
                foreach (var arrays in group) {
                    var arr = (JArray)arrays.JsonValue;
                    newArr.AddRange(arr);
                }

                // add just one array for the group/key/claim type
                payload.Add(group.Key, newArr.ToArray());
            }

            var unsupportedJsonTokens = jsonTokens.Except(jsonObjects).Except(jsonArrays).ToArray();
            var unsupportedJsonClaimTypes = unsupportedJsonTokens.Select(x => x.Type).Distinct().ToArray();
            if (unsupportedJsonClaimTypes.Any())
                throw new($"Unsupported JSON type for claim types: {unsupportedJsonClaimTypes.Aggregate((x, y) => x + ", " + y)}");

            return payload;
    }

    /// <summary>
    /// Applies the signature to the JWT
    /// </summary>
    /// <param name="jwt">The JWT object.</param>
    /// <returns>The signed JWT</returns>
    static async Task<string> CreateJwtAsync(SecurityToken jwt) => new JwtSecurityTokenHandler().WriteToken(jwt);
}