// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Models.Contexts;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.ResponseHandling.Default;

/// <summary>
/// The userinfo response generator
/// </summary>
/// <seealso cref="IdentityServer4.ResponseHandling.IUserInfoResponseGenerator" />
public sealed class UserInfoResponseGenerator : IUserInfoResponseGenerator
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// The profile service
    /// </summary>
    readonly IProfileService profile;

    /// <summary>
    /// The resource store
    /// </summary>
    readonly IResourceStore resources;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserInfoResponseGenerator"/> class.
    /// </summary>
    /// <param name="profile">The profile.</param>
    /// <param name="resourceStore">The resource store.</param>
    /// <param name="logger">The logger.</param>
    public UserInfoResponseGenerator(IProfileService profile, IResourceStore resourceStore, ILogger<UserInfoResponseGenerator> logger)
    {
        this.profile = profile;
        resources = resourceStore;
        this.logger = logger;
    }

    /// <summary>
    /// Creates the response.
    /// </summary>
    /// <param name="validationResult">The userinfo request validation result.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">Profile service returned incorrect subject value</exception>
    public async Task<Dictionary<string, object>> ProcessAsync(UserInfoRequestValidationResult validationResult)
    {
        logger.LogDebug("Creating userinfo response");

        // extract scopes and turn into requested claim types
        var scopes = validationResult.TokenValidationResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope).Select(c => c.Value).ToArray();

        var validatedResources = await GetRequestedResourcesAsync(scopes);
        var requestedClaimTypes = await validatedResources.MapT(GetRequestedClaimTypesAsync).IfNoneAsync(Array.Empty<string>());

        logger.LogDebug("Requested claim types: {ClaimTypes}", requestedClaimTypes.ToSpaceSeparatedString());

        // call profile service
        var context = new ProfileDataRequestContext(validationResult.Subject,
                                                    validationResult.TokenValidationResult.Client,
                                                    IdentityServerConstants.ProfileDataCallers.UserInfoEndpoint,
                                                    requestedClaimTypes);

        var profileClaims = await profile.GetIssuedClaims(context);

        // construct outgoing claims
        var outgoingClaims = new List<Claim>();

        outgoingClaims.AddRange(profileClaims);
        logger.LogInformation("Profile service returned the following claim types: {Types}", profileClaims.Select(c => c.Type).ToSpaceSeparatedString());

        var subClaim = outgoingClaims.SingleOrDefault(x => x.Type == JwtClaimTypes.Subject);
        if (subClaim == null)
        {
            outgoingClaims.Add(new(JwtClaimTypes.Subject, validationResult.Subject.GetRequiredSubjectId()));
        }
        else if (subClaim.Value != validationResult.Subject.GetRequiredSubjectId())
        {
            logger.LogError("Profile service returned incorrect subject value: {Sub}", subClaim);
            throw new InvalidOperationException("Profile service returned incorrect subject value");
        }

        return outgoingClaims.ToClaimsDictionary();
    }

    /// <summary>
    ///  Gets the identity resources from the scopes.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    async Task<Option<ResourceValidationResult>> GetRequestedResourcesAsync(string[] scopes)
    {
        if (!scopes.Any())
            return None;

        var scopeString = string.Join(" ", scopes);
        logger.LogDebug("Scopes in access token: {Scopes}", scopeString);

        // if we ever parameterize identity scopes, then we would need to invoke the resource validator's parse API here
        var identityResources = await resources.FindEnabledIdentityResourcesByScopeAsync(scopes);

        return new ResourceValidationResult(new (identityResources, Enumerable.Empty<ApiResource>(), Enumerable.Empty<ApiScope>()));
    }

    /// <summary>
    /// Gets the requested claim types.
    /// </summary>
    /// <param name="resourceValidationResult"></param>
    /// <returns></returns>
    static Task<string[]> GetRequestedClaimTypesAsync(ResourceValidationResult resourceValidationResult)
    {
        var identityResources = resourceValidationResult.Resources.IdentityResources;
        var result = identityResources.SelectMany(x => x.UserClaims).Distinct().ToArray();
        return Task.FromResult(result);
    }
}