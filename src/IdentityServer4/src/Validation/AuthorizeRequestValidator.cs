// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Immutable;
using System.Linq;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Models;
using IdentityServer4.Models.Contexts;
using IdentityServer4.Services;
using IdentityServer4.Validation.Default;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Primitives;

namespace IdentityServer4.Validation;

/// <summary>
/// Validation helper for authorization flows
/// </summary>
public static class AuthorizeRequestValidator
{
    /// <summary>
    /// Get validated request URI
    /// </summary>
    /// <param name="options"></param>
    /// <param name="jwtRequestClient"></param>
    /// <param name="client"></param>
    /// <param name="request"></param>
    /// <param name="requestUri"></param>
    /// <returns></returns>
    /// <exception cref="BadRequestException"></exception>
    public static async Task<Option<string>> GetOidcRequest(IdentityServerOptions options, IJwtRequestUriHttpClient jwtRequestClient, Client client, Option<string> request,
                                                            Option<string> requestUri) {
        if (request.IsSome && requestUri.IsSome)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Both request and request_uri are present");

        if (!options.Endpoints.EnableJwtRequestUri && requestUri.IsSome)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.RequestUriNotSupported, "request_uri present but config prohibits");
        var jwtRequest = options.Endpoints.EnableJwtRequestUri
                             ? await requestUri.MapT(jv => jwtRequestClient.GetJwtAsync(jv, client)
                                                                           .GetOrThrow(() => new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequestUri,
                                                                                                                     "no value returned from request_uri")))
                                               .OrElse(request)
                             : request;

        // previously, RequestObject
        return jwtRequest.Map(ValidateLength(OidcConstants.AuthorizeRequest.Request, options.InputLengthRestrictions.Jwt));
    }

    /// <summary>
    /// Get claims of jwtRequest
    /// </summary>
    /// <returns></returns>
    public static async Task<IEnumerable<(string, string)>> ValidateClaimsFromToken(JwtRequestValidator jwtValidator, ImmutableDictionary<string, StringValues> parameters,
                                                                                    Client client, ResponseType responseType, string jwtRequest) {
        var payload = await jwtValidator.GetTokenRawClaim(client, jwtRequest);

        if (payload.TryGetValue(OidcConstants.AuthorizeRequest.ResponseType, out var payloadResponseType) && ResponseType.Create(payloadResponseType) != responseType)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequestObject, "response_type in JWT payload does not match response_type in request");

        if (payload.TryGetValue(OidcConstants.AuthorizeRequest.ClientId, out var payloadClientId)) {
            if (!string.Equals(client.ClientId, payloadClientId, StringComparison.Ordinal))
                throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "client_id in JWT payload does not match client_id in request");
        }
        else
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequestObject, "client_id is missing in JWT payload");

        var (existed, newParams) = payload.Where(i => i.Key is not (JwtClaimTypes.Issuer or JwtClaimTypes.Audience))
                                          .Partition(i => parameters.ContainsKey(i.Key));
        var invalidValue = existed.TryFirst(i => parameters[i.Key].ToString() != i.Value);
        if (invalidValue.IsSome)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"{invalidValue.Get().Key} in JWT payload does not match query string parameter");

        // previously, RequestObjectValues
        return newParams.Select(pairs => (pairs.Key, pairs.Value));
    }

    /// <summary>
    /// Validate context
    /// </summary>
    /// <param name="data"></param>
    /// <exception cref="BadRequestException"></exception>
    public static void ValidateContext(AuthContext data)
    {
        if (!data.Client.AllowedGrantTypes.Contains(data.GrantType))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.UnauthorizedClient, $"Invalid grant type {data.GrantType} for client {data.Client.ClientId}");

        if (data.ResponseType.HasToken && !data.Client.AllowAccessTokensViaBrowser)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest,
                                          "Client requested access token - but client is not configured to receive access tokens via browser");

        var resourceHasIdentity = data.Resources.Any(r => r is IdentityResource);
        var resourceHasApiScope = data.Resources.Any(r => r is ApiScope);
        var scopeRequirement = data.ResponseType.GetScopeRequirement();

        if (scopeRequirement == Constants.ScopeRequirement.Identity && !resourceHasIdentity)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, "Requests for id_token response type must include identity scopes");
        if (scopeRequirement == Constants.ScopeRequirement.IdentityOnly && (!resourceHasIdentity || resourceHasApiScope))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, "Requests for id_token response type only must not include resource scopes");
        if (scopeRequirement == Constants.ScopeRequirement.ResourceOnly && (resourceHasIdentity || !resourceHasApiScope))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, "Requests for token response type only must include resource scopes, but no identity scopes");

        var isOpenId = data.Scopes.Contains(IdentityServerConstants.StandardScopes.OpenId);
        if (!isOpenId && scopeRequirement is Constants.ScopeRequirement.Identity or Constants.ScopeRequirement.IdentityOnly)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "response_type requires the openid scope");

        if (!isOpenId && resourceHasIdentity)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, "Identity related scope requests, but no openid scope");

        if (isOpenId && data.Nonce.IsNone && data.GrantType is GrantType.Implicit or GrantType.Hybrid)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Nonce required for implicit and hybrid flow with openid scope");
    }

    /// <summary>
    /// Validate string max length
    /// </summary>
    /// <param name="name"></param>
    /// <param name="validLength"></param>
    /// <returns></returns>
    /// <exception cref="BadRequestException"></exception>
    public static Func<string, string> ValidateLength(string name, int validLength) => s => {
        if (s.Length > validLength)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too long");
        return s;
    };

    /// <summary>
    /// Validate string length's range
    /// </summary>
    /// <param name="name"></param>
    /// <param name="minLength"></param>
    /// <param name="maxLength"></param>
    /// <returns></returns>
    /// <exception cref="BadRequestException"></exception>
    public static Func<string, string> ValidateLength(string name, int minLength, int maxLength) => s => {
        if (s.Length < minLength)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too short");
        if (s.Length > maxLength)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too long");
        return s;
    };
}