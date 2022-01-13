// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.ResponseHandling;

/// <summary>
/// The default token response generator
/// </summary>
/// <seealso cref="IdentityServer4.ResponseHandling.ITokenResponseGenerator" />
public sealed class TokenResponseGenerator : ITokenResponseGenerator
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// The token service
    /// </summary>
    readonly ITokenService tokenService;

    /// <summary>
    /// The refresh token service
    /// </summary>
    readonly IRefreshTokenService refreshTokenService;

    /// <summary>
    /// The scope parser
    /// </summary>
    public IScopeParser ScopeParser { get; }

    /// <summary>
    /// The resource store
    /// </summary>
    readonly IResourceStore resources;

    /// <summary>
    /// The clients store
    /// </summary>
    readonly IClientStore clients;

    /// <summary>
    ///  The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenResponseGenerator" /> class.
    /// </summary>
    /// <param name="clock">The clock.</param>
    /// <param name="tokenService">The token service.</param>
    /// <param name="refreshTokenService">The refresh token service.</param>
    /// <param name="scopeParser">The scope parser.</param>
    /// <param name="resources">The resources.</param>
    /// <param name="clients">The clients.</param>
    /// <param name="logger">The logger.</param>
    public TokenResponseGenerator(ISystemClock clock, ITokenService tokenService, IRefreshTokenService refreshTokenService, IScopeParser scopeParser, IResourceStore resources, IClientStore clients, ILogger<TokenResponseGenerator> logger)
    {
        this.clock = clock;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        ScopeParser = scopeParser;
        this.resources = resources;
        this.clients = clients;
        this.logger = logger;
    }

    /// <summary>
    /// Processes the response.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    public async Task<TokenResponse> ProcessAsync(TokenRequestValidationResult request)
    {
        switch (request.ValidatedRequest.GrantType)
        {
            case OidcConstants.GrantTypes.ClientCredentials:
                return await ProcessClientCredentialsRequestAsync(request);
            case OidcConstants.GrantTypes.Password:
                return await ProcessPasswordRequestAsync(request);
            case OidcConstants.GrantTypes.AuthorizationCode:
                return await ProcessAuthorizationCodeRequestAsync(request);
            case OidcConstants.GrantTypes.RefreshToken:
                return await ProcessRefreshTokenRequestAsync(request);
            case OidcConstants.GrantTypes.DeviceCode:
                return await ProcessDeviceCodeRequestAsync(request);
            default:
                return await ProcessExtensionGrantRequestAsync(request);
        }
    }

    /// <summary>
    /// Creates the response for an client credentials request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    Task<TokenResponse> ProcessClientCredentialsRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for client credentials request");

        return ProcessTokenRequestAsync(request);
    }

    /// <summary>
    /// Creates the response for a password request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    Task<TokenResponse> ProcessPasswordRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for password request");

        return ProcessTokenRequestAsync(request);
    }

    /// <summary>
    /// Creates the response for an authorization code request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">Client does not exist anymore.</exception>
    async Task<TokenResponse> ProcessAuthorizationCodeRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for authorization code request");

        //////////////////////////
        // access token
        /////////////////////////
        var (accessToken, refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);
        var response = new TokenResponse(accessToken,
                                         request.ValidatedRequest.AccessTokenLifetime,
                                         request.CustomResponse,
                                         request.ValidatedRequest.AuthorizationCode.RequestedScopes.ToSpaceSeparatedString());

        //////////////////////////
        // refresh token
        /////////////////////////
        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }

        //////////////////////////
        // id token
        /////////////////////////
        if (request.ValidatedRequest.AuthorizationCode.IsOpenId)
        {
            // load the client that belongs to the authorization code
            await GetValidatedClient(request.ValidatedRequest.AuthorizationCode.ClientId!);

            var parsedScopesResult = ScopeParser.ParseScopeValues(request.ValidatedRequest.AuthorizationCode.RequestedScopes);
            var validatedResources = await resources.FindAllResources(parsedScopesResult);

            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.AuthorizationCode.Subject,
                ValidatedResources = validatedResources,
                Nonce = request.ValidatedRequest.AuthorizationCode.Nonce,
                AccessTokenToHash = response.AccessToken,
                StateHash = request.ValidatedRequest.AuthorizationCode.StateHash,
                ValidatedRequest = request.ValidatedRequest
            };

            response.IdentityToken = await tokenService.CreateIdentityToken();
        }

        return response;
    }

    /// <summary>
    /// Creates the response for a refresh token request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    async Task<TokenResponse> ProcessRefreshTokenRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for refresh token request");

        var oldAccessToken = request.ValidatedRequest.RefreshToken.AccessToken;
        string accessTokenString;

        if (request.ValidatedRequest.Client.UpdateAccessTokenClaimsOnRefresh)
        {
            var subject = request.ValidatedRequest.RefreshToken.Subject;

            // todo: do we want to just parse here and build up validated result
            // or do we want to fully re-run validation here.
            var parsedScopesResult = ScopeParser.ParseScopeValues(oldAccessToken.Scopes);
            var validatedResources = await resources.FindAllResources(parsedScopesResult);

            var creationRequest = new TokenCreationRequest
            {
                Subject = subject,
                Description = request.ValidatedRequest.RefreshToken.Description,
                ValidatedRequest = request.ValidatedRequest,
                ValidatedResources = validatedResources
            };

            var newAccessToken = await tokenService.CreateAccessTokenAsync(creationRequest);
            accessTokenString = await tokenService.CreateSecurityTokenAsync(newAccessToken);
        }
        else
        {
            oldAccessToken.CreationTime = clock.UtcNow.UtcDateTime;
            oldAccessToken.Lifetime = request.ValidatedRequest.AccessTokenLifetime;

            accessTokenString = await tokenService.CreateSecurityTokenAsync(oldAccessToken);
        }

        var handle = await refreshTokenService.UpdateRefreshTokenAsync(request.ValidatedRequest.RefreshTokenHandle, request.ValidatedRequest.RefreshToken, request.ValidatedRequest.Client);

        return new(){
            IdentityToken = (await CreateIdTokenFromRefreshTokenRequestAsync(request.ValidatedRequest, accessTokenString)).Get(),
            AccessToken = accessTokenString,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            RefreshToken = handle,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.RefreshToken.Scopes.ToSpaceSeparatedString()
        };
    }

    /// <summary>
    /// Processes the response for device code grant request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    async Task<TokenResponse> ProcessDeviceCodeRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for device code request");

        //////////////////////////
        // access token
        /////////////////////////
        var (accessToken, refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.DeviceCode.AuthorizedScopes.ToSpaceSeparatedString()
        };

        //////////////////////////
        // refresh token
        /////////////////////////
        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }

        //////////////////////////
        // id token
        /////////////////////////
        if (request.ValidatedRequest.DeviceCode.IsOpenId)
        {
            // load the client that belongs to the device code
            await GetValidatedClient(request.ValidatedRequest.DeviceCode.ClientId!);

            var parsedScopesResult = ScopeParser.ParseScopeValues(request.ValidatedRequest.DeviceCode.AuthorizedScopes);
            var validatedResources = await resources.FindAllResources(parsedScopesResult);

            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.DeviceCode.Subject,
                ValidatedResources = validatedResources,
                AccessTokenToHash = response.AccessToken,
                ValidatedRequest = request.ValidatedRequest
            };

            var idToken = await tokenService.CreateIdentityTokenAsync(tokenRequest);
            var jwt = await tokenService.CreateSecurityTokenAsync(idToken);
            response.IdentityToken = jwt;
        }

        return response;
    }

    /// <summary>
    /// Creates the response for an extension grant request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    Task<TokenResponse> ProcessExtensionGrantRequestAsync(TokenRequestValidationResult request)
    {
        logger.LogTrace("Creating response for extension grant request");

        return ProcessTokenRequestAsync(request);
    }

    /// <summary>
    /// Creates the response for a token request.
    /// </summary>
    /// <param name="validationResult">The validation result.</param>
    /// <returns></returns>
    async Task<TokenResponse> ProcessTokenRequestAsync(TokenRequestValidationResult validationResult)
    {
        (var accessToken, var refreshToken) = await CreateAccessTokenAsync(validationResult.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = validationResult.ValidatedRequest.AccessTokenLifetime,
            Custom = validationResult.CustomResponse,
            Scope = validationResult.ValidatedRequest.ValidatedResources.RawScopeValues.ToSpaceSeparatedString()
        };

        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }

        return response;
    }

    /// <summary>
    /// Creates the access/refresh token.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">Client does not exist anymore.</exception>
    async Task<(string accessToken, string? refreshToken)> CreateAccessTokenAsync(ValidatedTokenRequest request)
    {
        TokenCreationRequest tokenRequest;
        bool createRefreshToken;

        var authModel = (IAuthorizationModel?) request.AuthorizationCode ?? request.DeviceCode;

        if (authModel != null)
            (createRefreshToken, tokenRequest) = await CreateToken(request, authModel);
        else
        {
            createRefreshToken = request.ValidatedResources.Resources.OfflineAccess;

            tokenRequest = new()
            {
                Subject = request.Subject,
                ValidatedResources = request.ValidatedResources,
                ValidatedRequest = request
            };
        }

        var at = await tokenService.CreateAccessTokenAsync(tokenRequest);
        var accessToken = await tokenService.CreateSecurityTokenAsync(at);

        if (createRefreshToken)
        {
            var refreshToken = await refreshTokenService.CreateRefreshTokenAsync(tokenRequest.Subject, at, request.Client);
            return (accessToken, refreshToken);
        }

        return (accessToken, null);
    }

    async Task<(bool, TokenCreationRequest)> CreateToken(ValidatedRequest request, IAuthorizationModel model)
    {
        var createRefreshToken = model.Scopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess);

        await GetValidatedClient(model.ClientId!);

        var parsedScopesResult = ScopeParser.ParseScopeValues(model.Scopes);
        var validatedResources = await resources.FindAllResources(parsedScopesResult);

        var tokenRequest = new TokenCreationRequest
        {
            Subject = model.Subject,
            Description = model.Description,
            ValidatedResources = validatedResources,
            ValidatedRequest = request
        };
        return (createRefreshToken, tokenRequest);
    }

    /// <summary>
    /// Creates an id_token for a refresh token request if identity resources have been requested.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="newAccessToken">The new access token.</param>
    /// <returns></returns>
    async Task<Option<string>> CreateIdTokenFromRefreshTokenRequestAsync(ValidatedTokenRequest request, string newAccessToken)
    {
        // todo: can we just check for "openid" scope?
        //var identityResources = await Resources.FindEnabledIdentityResourcesByScopeAsync(request.RefreshToken.Scopes);
        //if (identityResources.Any())

        if (request.RefreshToken.Scopes.Contains(OidcConstants.StandardScopes.OpenId))
        {
            var oldAccessToken = request.RefreshToken.AccessToken;

            var parsedScopesResult = ScopeParser.ParseScopeValues(oldAccessToken.Scopes);
            var validatedResources = await resources.FindAllResources(parsedScopesResult);

            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.RefreshToken.Subject,
                ValidatedResources = validatedResources,
                ValidatedRequest = request,
                AccessTokenToHash = newAccessToken
            };

            var idToken = await tokenService.CreateIdentityTokenAsync(tokenRequest);
            return await tokenService.CreateSecurityTokenAsync(idToken);
        }

        return None;
    }

    Task<Client> GetValidatedClient(Option<string> clientId) =>
        Task.FromResult(clientId)
            .BindAsync(clients.FindClientByIdAsync)
            .IfNone(() => throw new InvalidOperationException("Client does not exist anymore."));
}