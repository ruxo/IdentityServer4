// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Services;

/// <summary>
/// The claims service is responsible for determining which claims to include in tokens
/// </summary>
public interface IClaimsService
{
    /// <summary>
    /// Returns claims for an identity token
    /// </summary>
    /// <param name="session">The authenticated session.</param>
    /// <param name="resources">The resources.</param>
    /// <param name="includeAllIdentityClaims">Specifies if all claims should be included in the token, or if the userinfo endpoint can be used to retrieve them</param>
    /// <param name="request">The raw request</param>
    /// <returns>
    /// Claims for the identity token
    /// </returns>
    [Obsolete("Use GetIdentityTokenClaimsAsync below")]
    Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(UserSession session, ResourceValidationResult resources, bool includeAllIdentityClaims, ValidatedRequest request);

    /// <summary>
    /// Returns claims for an identity token
    /// </summary>
    /// <param name="session">The authenticated session.</param>
    /// <param name="client">Current client</param>
    /// <param name="resources">Parsed resources</param>
    /// <param name="includeAllIdentityClaims"></param>
    /// <returns></returns>
    Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(UserSession session, Client client, IEnumerable<Resource> resources, bool includeAllIdentityClaims);

    /// <summary>
    /// Returns claims for an access token.
    /// </summary>
    /// <param name="session">The authenticated session.</param>
    /// <param name="client">The authenticating client</param>
    /// <param name="scopes">The requested scopes.</param>
    /// <param name="resources">Resources from <paramref name="scopes"/></param>
    /// <returns>
    /// Claims for the access token
    /// </returns>
    Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(UserSession session, Client client, ImmutableHashSet<string> scopes, IEnumerable<Resource> resources);
}