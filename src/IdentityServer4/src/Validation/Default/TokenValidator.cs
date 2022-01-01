// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.Validation.Default;

class TokenValidator : ITokenValidator
{
    readonly ILogger logger;
    readonly IdentityServerOptions options;
    readonly IHttpContextAccessor context;
    readonly IReferenceTokenStore referenceTokenStore;
    readonly ICustomTokenValidator customValidator;
    readonly IClientStore clients;
    readonly IProfileService profile;
    readonly IKeyMaterialService keyService;
    readonly ISystemClock clock;

    public TokenValidator(
        IdentityServerOptions options,
        IHttpContextAccessor context,
        IClientStore clients,
        IProfileService profile,
        IReferenceTokenStore referenceTokenStore,
        ICustomTokenValidator customValidator,
        IKeyMaterialService keyService,
        ISystemClock clock,
        ILogger<TokenValidator> logger)
    {
        this.options = options;
        this.context = context;
        this.clients = clients;
        this.profile = profile;
        this.referenceTokenStore = referenceTokenStore;
        this.customValidator = customValidator;
        this.keyService = keyService;
        this.clock = clock;
        this.logger = logger;
    }

    public async Task<Either<ErrorInfo, ValidatedJwtAccessToken>> ValidateIdentityTokenAsync(string token, string? clientId = null, bool validateLifetime = true)
    {
        logger.LogDebug("Start identity token validation");

        var tokenError = ValidateToken(AccessTokenType.Jwt, token);
        if (tokenError.IsSome)
            return tokenError.Get();

        clientId ??= GetClientIdFromJwt(token);

        if (clientId.IsMissing()) {
            logger.LogError("No clientId supplied, can't find id in identity token");
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        var client = await clients.FindEnabledClientByIdAsync(clientId);
        if (client.IsNone)
        {
            logger.LogError("Unknown or disabled client: {ClientId}", clientId);
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        logger.LogDebug("Client found: {ClientId} / {ClientName}", client.Get().ClientId, client.Get().ClientName);

        var keys = await keyService.GetValidationKeysAsync().ToArrayAsync();
        var result = await ValidateJwtAsync(token, keys, audience: clientId, validateLifetime: validateLifetime);

        if (result.IsLeft)
        {
            logger.LogError("Error validating JWT: {Error}", result.GetLeft());
            return result;
        }

        logger.LogDebug("Calling into custom token validator: {Type}", customValidator.GetType().FullName);
        var customResult = await customValidator.ValidateIdentityTokenAsync(token, result.GetRight());

        if (customResult.IsSome)
        {
            logger.LogError("Custom validator failed: {Error}", customResult.Get());
            return customResult.Get();
        }

        LogSuccess(new{
            Token = token,
            ValidationResult = result.GetRight()
        });
        return result;
    }

    int GetTokenLength(AccessTokenType type) =>
        type switch{
            AccessTokenType.Jwt => options.InputLengthRestrictions.Jwt,
            AccessTokenType.Reference => options.InputLengthRestrictions.TokenHandle,
            _ => int.MaxValue
        };

    public async Task<Either<ErrorInfo, TokenValidationResult>> ValidateAccessTokenAsync(string token, string? expectedScope = null)
    {
        logger.LogTrace("Start access token validation");

        var tokenType = token.Contains(".") ? AccessTokenType.Jwt : AccessTokenType.Reference;

        var tokenError = ValidateToken(tokenType, token);
        if (tokenError.IsSome)
            return tokenError.Get();

        var result = tokenType == AccessTokenType.Jwt
                         ? await ValidateJwtAsync(token, await keyService.GetValidationKeysAsync().ToArrayAsync()).MapAsync(r => (TokenValidationResult)r)
                         : await ValidateReferenceAccessTokenAsync(token);

        if (result.IsLeft)
            return result;

        var tokenResult = result.GetRight();
        var claims = tokenResult.Claims;

        // make sure client is still active (if client_id claim is present)
        var clientClaim = claims.TryFirst(c => c.Type == JwtClaimTypes.ClientId);
        if (clientClaim.IsSome)
        {
            var client = await clients.FindEnabledClientByIdAsync(clientClaim.Get().Value);
            if (client.IsNone)
            {
                logger.LogError("Client deleted or disabled: {ClientId}", clientClaim.Get().Value);

                return new ErrorInfo(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        // make sure user is still active (if sub claim is present)
        var subClaim = claims.TryFirst(c => c.Type == JwtClaimTypes.Subject);
        if (subClaim.IsSome)
        {
            var principal = Principal.Create("tokenvalidator", claims);

            if (tokenResult is ValidatedReferenceAccessToken t)
                principal.Identities.First().AddClaim(new (JwtClaimTypes.ReferenceTokenId, t.ReferenceTokenId));

            var isActive = await profile.IsActiveAsync(principal, tokenResult.Client, IdentityServerConstants.ProfileIsActiveCallers.AccessTokenValidation);

            if (!isActive)
            {
                logger.LogError("User marked as not active: {Subject}", subClaim.Get().Value);
                return new ErrorInfo(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        // check expected scope(s)
        if (expectedScope.IsPresent())
        {
            var scope = claims.TryFirst(c => c.Type == JwtClaimTypes.Scope && c.Value == expectedScope);
            if (scope.IsNone)
            {
                logger.LogError("Checking for expected scope {ExpectedScope} failed", expectedScope);
                return new ErrorInfo(OidcConstants.ProtectedResourceErrors.InsufficientScope);
            }
        }

        logger.LogDebug("Calling into custom token validator: {Type}", customValidator.GetType().FullName);
        var customResult = await customValidator.ValidateAccessTokenAsync(token, tokenResult);

        if (customResult.IsSome)
        {
            logger.LogError("Custom validator failed: {Error}", customResult.Get());
            return customResult.Get();
        }

        // add claims again after custom validation

        LogSuccess(new{
            ExpectedScope= expectedScope,
            ValidateLifetime = true,
            Claims = tokenResult.Claims.ToClaimsDictionary()
        });
        return result;
    }

    async Task<Either<ErrorInfo, ValidatedJwtAccessToken>> ValidateJwtAsync(string jwt, IEnumerable<SecurityKeyInfo> validationKeys, bool validateLifetime = true,
                                                                                  string? audience = null) {
        var handler = new JwtSecurityTokenHandler();
        handler.InboundClaimTypeMap.Clear();

        var audienceIsPresent = audience.IsPresent();
        var parameters = new TokenValidationParameters{
            ValidIssuer = context.HttpContext!.GetIdentityServerIssuerUri(),
            IssuerSigningKeys = validationKeys.Select(k => k.Key),
            ValidateLifetime = validateLifetime,
            ValidateActor = audienceIsPresent,
            ValidAudience = audienceIsPresent ? audience : null
        };

        try {
            var id = handler.ValidateToken(jwt, parameters, out var securityToken);
            var jwtSecurityToken = (JwtSecurityToken)securityToken;

            // if no audience is specified, we make at least sure that it is an access token
            if (audience.IsMissing() && options.AccessTokenJwtType.IsPresent()) {
                var type = jwtSecurityToken.Header.Typ;
                if (!string.Equals(type, options.AccessTokenJwtType))
                    return new ErrorInfo("invalid JWT token type");
            }

            // if access token contains an ID, log it
            if (logger.IsEnabled(LogLevel.Debug)) {
                var jwtId = id.FindFirst(JwtClaimTypes.JwtId);
                if (jwtId != null)
                    logger.LogDebug("Principal from {Jwt} contains {JwtId}", jwt, jwtId);
            }

            // load the client that belongs to the client_id claim
            var clientId = id.FindFirst(JwtClaimTypes.ClientId);
            if (clientId == null) throw new InvalidOperationException("No Client ID!?");

            var client = await clients.FindEnabledClientByIdAsync(clientId.Value);
            if (client.IsNone)
                throw new InvalidOperationException("Client does not exist anymore.");

            var claims = id.Claims.ToList();

            // check the scope format (array vs space delimited string)
            var scopes = claims.Where(c => c.Type == JwtClaimTypes.Scope).ToArray();
            foreach (var scope in scopes)
                if (scope.Value.Contains(" ")) {
                    claims.Remove(scope);

                    var values = scope.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    claims.AddRange(values.Select(value => new Claim(JwtClaimTypes.Scope, value)));
                }

            return new ValidatedJwtAccessToken(client.Get(), claims.ToArray(), jwt);
        }
        catch (SecurityTokenExpiredException expiredException) {
            logger.LogInformation(expiredException, "JWT token validation error: {Exception}", expiredException.Message);
            return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
        }
        catch (Exception ex) {
            logger.LogError(ex, "JWT token validation error: {Exception}", ex.Message);
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }
    }

    async Task<Either<ErrorInfo, TokenValidationResult>> ValidateReferenceAccessTokenAsync(string tokenHandle)
    {
        var t = await referenceTokenStore.GetReferenceTokenAsync(tokenHandle);

        if (t.IsNone)
        {
            logger.LogError("Invalid reference token {Token}", tokenHandle);
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }
        var token = t.Get();

        if (token.CreationTime.HasExceeded(token.Lifetime, clock.UtcNow.UtcDateTime))
        {
            logger.LogError("Token expired: Created since {Time}", token.CreationTime);

            await referenceTokenStore.RemoveReferenceTokenAsync(tokenHandle);
            return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
        }

        // load the client that is defined in the token
        var client = await clients.FindEnabledClientByIdAsync(token.ClientId);
        if (client.IsNone)
        {
            logger.LogError("Client deleted or disabled: {TokenClientId}", token.ClientId);
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        return new ValidatedReferenceAccessToken(client.Get(),  ReferenceTokenToClaims(token).ToArray(),  token,  tokenHandle );
    }

    static IEnumerable<Claim> ReferenceTokenToClaims(Token token) {
        yield return new(JwtClaimTypes.Issuer, token.Issuer);
        yield return new(JwtClaimTypes.NotBefore, new DateTimeOffset(token.CreationTime).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64);
        yield return new(JwtClaimTypes.Expiration, new DateTimeOffset(token.CreationTime).AddSeconds(token.Lifetime).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64);

        foreach (var aud in token.Audiences)
            yield return new(JwtClaimTypes.Audience, aud);

        foreach (var c in token.Claims)
            yield return c;
    }

    static string GetClientIdFromJwt(string token) => new JwtSecurityToken(token).Audiences.First();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static ErrorInfo Invalid(string error) => new(error);

    void LogSuccess(object data) => logger.LogDebug("Token validation success\n{@LogMessage}", data);

    Option<ErrorInfo> ValidateToken(AccessTokenType type, string token) {
        if (token.Length > GetTokenLength(type))
        {
            logger.LogError("{TokenType} token is too long", type);

            return new ErrorInfo(OidcConstants.ProtectedResourceErrors.InvalidToken,  "Token too long" );
        }
        return None;
    }
}