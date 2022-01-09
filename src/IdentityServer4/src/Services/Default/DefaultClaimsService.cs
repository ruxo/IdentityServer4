// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Immutable;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Validation.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services;

/// <summary>
/// Default claims provider implementation
/// </summary>
public sealed class DefaultClaimsService : IClaimsService
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// The user service
    /// </summary>
    readonly IProfileService profile;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultClaimsService"/> class.
    /// </summary>
    /// <param name="profile">The profile service</param>
    /// <param name="logger">The logger</param>
    public DefaultClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger)
    {
        this.logger = logger;
        this.profile = profile;
    }

    /// <summary>
    /// Returns claims for an identity token
    /// </summary>
    /// <param name="subject">The subject</param>
    /// <param name="resources">The requested resources</param>
    /// <param name="includeAllIdentityClaims">Specifies if all claims should be included in the token, or if the userinfo endpoint can be used to retrieve them</param>
    /// <param name="request">The raw request</param>
    /// <returns>
    /// Claims for the identity token
    /// </returns>
    public async Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(UserSession session, ResourceValidationResult resources, bool includeAllIdentityClaims, ValidatedRequest request) {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public async Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(UserSession session, Client client, IEnumerable<Resource> resources, bool includeAllIdentityClaims) {
        var user = session.AuthenticatedUser;
        logger.LogDebug("Getting claims for identity token for subject: {Subject} and client: {ClientId}", user.SubjectId, client.ClientId);

        var outputClaims = new List<Claim>(GetStandardSubjectClaims(user));
        outputClaims.AddRange(GetOptionalClaims(user));

        // fetch all identity claims that need to go into the id token
        if (includeAllIdentityClaims || client.AlwaysIncludeUserClaimsInIdToken)
        {
            // filter so we don't ask for claim types that we will eventually filter out
            var additionalClaimTypes = FilterRequestedClaimTypes(resources.OfType<IdentityResource>().SelectMany(identityResource => identityResource.UserClaims));

            var issuedClaims = await profile.GetIssuedClaims(additionalClaimTypes, session);

            outputClaims.AddRange(FilterProtocolClaims(issuedClaims));
        }
        else
            logger.LogDebug("In addition to an id_token, an access_token was requested. No claims other than sub are included in the id_token. To obtain more user claims, either use the user info endpoint or set AlwaysIncludeUserClaimsInIdToken on the client configuration");

        return outputClaims;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(UserSession session, Client client, ImmutableHashSet<string> scopes, IEnumerable<Resource> resources) {
        var clientId = client.ClientId;
        var user = session.AuthenticatedUser;
        logger.LogDebug("Getting claims for access token for client: {ClientId}", clientId);

        var clientIdClaim = Enumerable.Repeat(new Claim(JwtClaimTypes.ClientId, clientId), 1);

        var claimTypes = client.AlwaysSendClientClaims
                             ? from claim in client.Claims
                               let claimType = client.ClientClaimsPrefix.IsPresent() ? client.ClientClaimsPrefix + claim.Type : claim.Type
                               select new Claim(claimType, claim.Value, claim.ValueType)
                             : Enumerable.Empty<Claim>();

        // we use the ScopeValues collection rather than the Resources.Scopes because we support dynamic scope values
        // from the request, so this issues those in the token.
        var scopeClaims = scopes.Select(scope => new Claim(JwtClaimTypes.Scope, scope));

        logger.LogDebug("Getting claims for access token for subject: {Subject}", user.SubjectId);

        var standardSubjectClaims = GetStandardSubjectClaims(user);
        var optionalClaims = GetOptionalClaims(user);

        // fetch all resource claims that need to go into the access token
        // filter so we don't ask for claim types that we will eventually filter out
        var additionalClaimTypes = FilterRequestedClaimTypes(resources.Where(r => r is ApiResource or ApiScope).SelectMany(i => i.UserClaims));
        var issuedClaims = await profile.GetIssuedClaims(additionalClaimTypes.Distinct(), session);
        var protocolClaims = FilterProtocolClaims(issuedClaims);

        return clientIdClaim.Append(claimTypes).Append(scopeClaims).Append(standardSubjectClaims).Append(optionalClaims).Append(protocolClaims);
    }

    /// <summary>
    /// Gets the standard subject claims.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <returns>A list of standard claims</returns>
    IEnumerable<Claim> GetStandardSubjectClaims(AuthenticatedUser subject)
    {
        yield return new(JwtClaimTypes.Subject, subject.SubjectId);
        yield return new(JwtClaimTypes.AuthenticationTime, subject.AuthenticationTimeEpoch.ToString(), ClaimValueTypes.Integer64);
        yield return new(JwtClaimTypes.IdentityProvider, subject.IdentityProvider);

        foreach (var method in subject.AuthenticationMethods)
            yield return method;
    }

    /// <summary>
    /// Gets additional (and optional) claims from the cookie or incoming subject.
    /// </summary>
    /// <param name="user">The subject.</param>
    /// <returns>Additional claims</returns>
    IEnumerable<Claim> GetOptionalClaims(AuthenticatedUser user)
    {
        var acr = user.Subject.FindFirst(JwtClaimTypes.AuthenticationContextClassReference);
        return acr == null? Enumerable.Empty<Claim>() : Enumerable.Repeat(acr, 1);
    }

    /// <summary>
    /// Filters out protocol claims like amr, nonce etc..
    /// </summary>
    /// <param name="claims">The claims.</param>
    /// <returns></returns>
    IEnumerable<Claim> FilterProtocolClaims(IEnumerable<Claim> claims)
    {
        var c = Seq(claims);
        var claimsToFilter = c.Where(x => Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x.Type));
        if (claimsToFilter.Any())
        {
            var types = claimsToFilter.Select(x => x.Type);
            logger.LogDebug("Claim types from profile service that were filtered: {ClaimTypes}", types);
        }
        return c.Where(x => !Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x.Type));
    }

    /// <summary>
    /// Filters out protocol claims like amr, nonce etc..
    /// </summary>
    /// <param name="claimTypes">The claim types.</param>
    IEnumerable<string> FilterRequestedClaimTypes(IEnumerable<string> claimTypes) =>
        claimTypes.Where(x => !Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x));
}