// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Models.Contexts;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services;

/// <summary>
/// Default token service
/// </summary>
public sealed class DefaultTokenService : ITokenService
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// The HTTP context accessor
    /// </summary>
    readonly IHttpContextAccessor contextAccessor;

    /// <summary>
    /// The claims provider
    /// </summary>
    readonly IClaimsService claimsProvider;

    /// <summary>
    /// The reference token store
    /// </summary>
    readonly IReferenceTokenStore referenceTokenStore;

    /// <summary>
    /// The signing service
    /// </summary>
    readonly ITokenCreationService creationService;

    /// <summary>
    /// The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// The key material service
    /// </summary>
    readonly IKeyMaterialService keyMaterialService;

    /// <summary>
    /// The IdentityServer options
    /// </summary>
    readonly IdentityServerOptions options;

    readonly ITokenCreationService tokenCreationService;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTokenService" /> class.
    /// </summary>
    public DefaultTokenService(
        IClaimsService claimsProvider,
        IReferenceTokenStore referenceTokenStore,
        ITokenCreationService creationService,
        IHttpContextAccessor contextAccessor,
        ISystemClock clock,
        IKeyMaterialService keyMaterialService,
        IdentityServerOptions options,
        ITokenCreationService tokenCreationService,
        ILogger<DefaultTokenService> logger)
    {
        this.contextAccessor = contextAccessor;
        this.claimsProvider = claimsProvider;
        this.referenceTokenStore = referenceTokenStore;
        this.creationService = creationService;
        this.clock = clock;
        this.keyMaterialService = keyMaterialService;
        this.options = options;
        this.tokenCreationService = tokenCreationService;
        this.logger = logger;
    }

    /// <inheritdoc />
    public async Task<string> CreateIdentityToken(UserSession session, AuthContext data, Option<AccessToken> authToken, Option<string> authorizationCode, string issuerUri) {
        // TODO: Dom, add a test for this. validate the at and c hashes are correct for the id_token when the client's alg doesn't match the server default.
        var allowedSignInAlgorithms = data.Client.AllowedIdentityTokenSigningAlgorithms;
        var algorithm = await keyMaterialService.GetSigningAlgorithm(allowedSignInAlgorithms);

        string createHash(string s) => CryptoHelper.CreateHashClaimValue(s, algorithm);
        Func<string, Claim> createHashClaim(string claimType) => s => new(claimType, createHash(s));

        var tokenHash = authToken.Map(i => i.Token).Map(createHashClaim(JwtClaimTypes.AccessTokenHash));
        var authCodeToken = authorizationCode.Map(createHashClaim(JwtClaimTypes.AuthorizationCodeHash));
        var stateHash = data.State.Map(createHashClaim(JwtClaimTypes.StateHash));
        var sessionId = session.SessionId.Map(s => new Claim(JwtClaimTypes.SessionId, s));

        var identityClaims = await claimsProvider.GetIdentityTokenClaimsAsync(session, data.Client, data.Resources, includeAllIdentityClaims: !data.ResponseType.AccessTokenNeeded);
        var claims = data.Nonce.Map(n => new Claim(JwtClaimTypes.Nonce, n))
                         .Append(new Claim(JwtClaimTypes.IssuedAt, clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64))
                         .Concat(tokenHash)
                         .Concat(authCodeToken)
                         .Concat(stateHash)
                         .Concat(sessionId)
                         .Concat(identityClaims)
                         .ToArray();
        return await tokenCreationService.CreateTokenAsync(OidcConstants.TokenTypes.IdentityToken,
                                                           allowedSignInAlgorithms,
                                                           issuerUri,
                                                           data.Client.IdentityTokenLifetime,
                                                           new[]{ data.Client.ClientId },
                                                           claims,
                                                           None);

    }

    /// <summary>
    /// Creates an identity token.
    /// </summary>
    /// <param name="request">The token creation request.</param>
    /// <returns>
    /// An identity token
    /// </returns>
    public async Task<Token> CreateIdentityTokenAsync(TokenCreationRequest request)
    {
        logger.LogTrace("Creating identity token");
        request.Validate();

        // todo: Dom, add a test for this. validate the at and c hashes are correct for the id_token when the client's alg doesn't match the server default.
        var credential = await keyMaterialService.GetSigningCredentialsAsync(request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms);
        var signingAlgorithm = credential.Algorithm;

        // host provided claims
        var claims = new List<Claim>();

        // if nonce was sent, must be mirrored in id token
        if (request.Nonce.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.Nonce, request.Nonce));
        }

        // add iat claim
        claims.Add(new(JwtClaimTypes.IssuedAt, clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

        // add at_hash claim
        if (request.AccessTokenToHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.AccessTokenHash, CryptoHelper.CreateHashClaimValue(request.AccessTokenToHash, signingAlgorithm)));
        }

        // add c_hash claim
        if (request.AuthorizationCodeToHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.AuthorizationCodeHash, CryptoHelper.CreateHashClaimValue(request.AuthorizationCodeToHash, signingAlgorithm)));
        }

        // add s_hash claim
        if (request.StateHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.StateHash, request.StateHash));
        }

        // add sid if present
        if (request.ValidatedRequest.SessionId.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
        }

        claims.AddRange(await claimsProvider.GetIdentityTokenClaimsAsync(
                                                                         request.Subject,
                                                                         request.ValidatedResources,
                                                                         request.IncludeAllIdentityClaims,
                                                                         request.ValidatedRequest));

        var issuer = contextAccessor.HttpContext!.GetIdentityServerIssuerUri();

        var token = new Token(OidcConstants.TokenTypes.IdentityToken)
        {
            CreationTime = clock.UtcNow.UtcDateTime,
            Audiences = { request.ValidatedRequest.Client.ClientId },
            Issuer = issuer,
            Lifetime = request.ValidatedRequest.Client.IdentityTokenLifetime,
            Claims = claims.Distinct(new ClaimComparer()).ToList(),
            ClientId = request.ValidatedRequest.Client.ClientId,
            AccessTokenType = request.ValidatedRequest.AccessTokenType,
            AllowedSigningAlgorithms = request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms
        };

        return token;
    }

    public async Task<Token> CreateIdentityTokenAsync(Client client, Option<string> nonce)
    {
        logger.LogTrace("Creating identity token");

        // TODO: Dom, add a test for this. validate the at and c hashes are correct for the id_token when the client's alg doesn't match the server default.
        var credential = await keyMaterialService.GetSigningCredentialsAsync(client.AllowedIdentityTokenSigningAlgorithms);
        var signingAlgorithm = credential.Algorithm;

        // host provided claims
        var claims = new List<Claim>();

        // if nonce was sent, must be mirrored in id token
        nonce.Do(n => claims.Add(new(JwtClaimTypes.Nonce, n)));

        // add iat claim
        claims.Add(new(JwtClaimTypes.IssuedAt, clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

        // add at_hash claim
        if (request.AccessTokenToHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.AccessTokenHash, CryptoHelper.CreateHashClaimValue(request.AccessTokenToHash, signingAlgorithm)));
        }

        // add c_hash claim
        if (request.AuthorizationCodeToHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.AuthorizationCodeHash, CryptoHelper.CreateHashClaimValue(request.AuthorizationCodeToHash, signingAlgorithm)));
        }

        // add s_hash claim
        if (request.StateHash.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.StateHash, request.StateHash));
        }

        // add sid if present
        if (request.ValidatedRequest.SessionId.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
        }

        claims.AddRange(await claimsProvider.GetIdentityTokenClaimsAsync(
                                                                         request.Subject,
                                                                         request.ValidatedResources,
                                                                         request.IncludeAllIdentityClaims,
                                                                         request.ValidatedRequest));

        var issuer = contextAccessor.HttpContext!.GetIdentityServerIssuerUri();

        return new Token(OidcConstants.TokenTypes.IdentityToken,
                         client.ClientId,
                         null,
                         claims,
                         Confirmation: None,

                         )
        {
            CreationTime = clock.UtcNow.UtcDateTime,
            Audiences = { client.ClientId },
            Issuer = issuer,
            Lifetime = client.IdentityTokenLifetime,
            Claims = claims.Distinct(new ClaimComparer()).ToList(),
            ClientId = request.ValidatedRequest.Client.ClientId,
            AccessTokenType = request.ValidatedRequest.AccessTokenType,
            AllowedSigningAlgorithms = client.AllowedIdentityTokenSigningAlgorithms
        };
    }

    /// <summary>
    /// Creates an access token.
    /// </summary>
    /// <param name="request">The token creation request.</param>
    /// <returns>
    /// An access token
    /// </returns>
    public Task<Token> CreateAccessTokenAsync(TokenCreationRequest request) {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public async Task<Token> CreateAccessTokenAsync(AuthenticatedUser user, Option<string> sessionId, Client client, ImmutableHashSet<string> scopes,
                                                    Resource[] resources, Option<string> confirmation, Option<string> description) {
        logger.LogTrace("Creating access token");

        var tokenClaims = await claimsProvider.GetAccessTokenClaimsAsync(user, client, scopes, resources);

        var jwtClaims = client.IncludeJwtId
                            ? Enumerable.Repeat(new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)), 1)
                            : Enumerable.Empty<Claim>();

        var sessionClaim = sessionId.Map(sid => new Claim(JwtClaimTypes.SessionId, sid)).ToSeq();

        var claims = tokenClaims.Concat(jwtClaims)
                                .Concat(sessionClaim)
                                 // iat claim as required by JWT profile
                                .Append(new Claim(JwtClaimTypes.IssuedAt, clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

        var issuer = contextAccessor.HttpContext!.GetIdentityServerIssuerUri();

        // add aud based on ApiResources in the validated request
        var apiResourceAudiences = resources.Where(r => r is ApiResource).Select(r => r.Name);
        var aud = options.EmitStaticAudienceClaim
                      ? apiResourceAudiences.Append(string.Format(IdentityServerConstants.AccessTokenAudience, issuer.EnsureTrailingSlash()))
                      : apiResourceAudiences;

        // add cnf if present
        var confirm = await confirmation.OrElseAsync(async () => options.MutualTls.AlwaysEmitConfirmationClaim
                                                                     ? Optional((await contextAccessor.HttpContext!.Connection.GetClientCertificateAsync())!)
                                                                        .Map(c => c.CreateThumbprintCnf())
                                                                     : None);

        return new(OidcConstants.TokenTypes.AccessToken,
                   client.ClientId,
                   description,
                   claims.Distinct(new ClaimComparer()).ToArray(),
                   confirm,
                   resources.Where(r => r is ApiResource).Cast<ApiResource>().FindMatchingSigningAlgorithms(),
                   aud.ToArray(),
                   issuer,
                   clock.UtcNow.UtcDateTime,
                   client.AccessTokenLifetime,
                   client.AccessTokenType);
    }

    /// <summary>
    /// Creates a serialized and protected security token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <returns>
    /// A security token in serialized form
    /// </returns>
    /// <exception cref="System.InvalidOperationException">Invalid token type.</exception>
    public async Task<string> CreateSecurityTokenAsync(Token token)
    {
        if (token.Type == OidcConstants.TokenTypes.AccessToken)
        {
            if (token.AccessTokenType == AccessTokenType.Jwt)
                return await creationService.CreateTokenAsync(token);
            else
                return await referenceTokenStore.StoreReferenceTokenAsync(token);
        }
        else if (token.Type == OidcConstants.TokenTypes.IdentityToken)
            // CHECK AuthorizeEndPointBase's GetJwt!
            return await creationService.CreateTokenAsync(token);
        else
            throw new InvalidOperationException("Invalid token type.");
    }
}