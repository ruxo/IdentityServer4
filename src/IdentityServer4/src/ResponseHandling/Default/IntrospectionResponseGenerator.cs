// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.ResponseHandling.Default;

/// <summary>
/// The introspection response generator
/// </summary>
/// <seealso cref="IdentityServer4.ResponseHandling.IIntrospectionResponseGenerator" />
public sealed class IntrospectionResponseGenerator : IIntrospectionResponseGenerator
{
    /// <summary>
    /// Gets the events.
    /// </summary>
    /// <value>
    /// The events.
    /// </value>
    readonly IEventService events;

    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="IntrospectionResponseGenerator" /> class.
    /// </summary>
    /// <param name="events">The events.</param>
    /// <param name="logger">The logger.</param>
    public IntrospectionResponseGenerator(IEventService events, ILogger<IntrospectionResponseGenerator> logger)
    {
        this.events = events;
        this.logger = logger;
    }

    /// <summary>
    /// Processes the response.
    /// </summary>
    /// <param name="api"></param>
    /// <param name="validationResult">The validation result.</param>
    /// <returns></returns>
    public async Task<Option<IntrospectionResponse>> ProcessAsync(ApiResource api, TokenValidationResult validationResult)
    {
        logger.LogTrace("Creating introspection response");

        // expected scope not present
        if (!await AreExpectedScopesPresentAsync(api, validationResult))
            return None;

        logger.LogDebug("Creating introspection response for active token");

        var (claims, invalid) = validationResult.Claims.Where(c => c.Type != JwtClaimTypes.Scope).ToClaimsDictionary();
        if (invalid.Any())
            logger.LogWarning("Claims contained invalid values: {@Claims}", (object)invalid);

        // calculate scopes the caller is allowed to see
        var allowedScopes = api.Scopes;
        var scopes = validationResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope).Select(x => x.Value);
        scopes = scopes.Where(x => allowedScopes.Contains(x));
        var scope = scopes.ToSpaceSeparatedString();

        await events.RaiseAsync(TokenIntrospectionSuccessEvent.Create(api.Name, validationResult));
        return new IntrospectionResponse(scope, claims);
    }

    /// <summary>
    /// Checks if the API resource is allowed to introspect the scopes.
    /// </summary>
    async Task<bool> AreExpectedScopesPresentAsync(ApiResource api, TokenValidationResult validationResult)
    {
        var apiScopes = api.Scopes;
        var tokenScopes = Seq(validationResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope));

        var tokenScopesThatMatchApi = tokenScopes.Where(c => apiScopes.Contains(c.Value));

        if (tokenScopesThatMatchApi.Any())
            // at least one of the scopes the API supports is in the token
            return true;
        else {
            // no scopes for this API are found in the token
            logger.LogError("Expected scope {Scopes} is missing in token", (object)apiScopes);
            await events.RaiseAsync(TokenIntrospectionFailureEvent.Create(api.Name,
                                                                          "Expected scopes are missing",
                                                                          validationResult.Token,
                                                                          apiScopes,
                                                                          tokenScopes.Select(s => s.Value).ToArray()));
            return false;
        }
    }
}