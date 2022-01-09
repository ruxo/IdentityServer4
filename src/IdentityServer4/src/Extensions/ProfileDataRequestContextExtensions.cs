// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Models.Contexts;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Extensions;

/// <summary>
/// Extensions for ProfileDataRequestContext
/// </summary>
public static class ProfileDataRequestContextExtensions
{
    /// <summary>
    /// Filters the claims based on requested claim types.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="claims">The claims.</param>
    /// <returns></returns>
    [Pure]
    public static IEnumerable<Claim> FilterClaims(this ProfileDataRequestContext context, IEnumerable<Claim> claims) =>
        claims.IntersectBy(context.RequestedClaimTypes, c => c.Type);

    /// <summary>
    /// Logs the profile request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="logger">The logger.</param>
    public static void LogProfileRequest(this ProfileDataRequestContext context, ILogger logger) =>
        logger.LogDebug("Get profile called for subject {Subject} from client {Client} with claim types {ClaimTypes} via {Caller}",
                        context.Subject.GetRequiredSubjectId(),
                        context.Client.ClientName ?? context.Client.ClientId,
                        context.RequestedClaimTypes,
                        context.Caller);

    /// <summary>
    /// Logs the issued claims.
    /// </summary>
    public static void LogIssuedClaims(this IEnumerable<Claim> claims, ILogger logger)
    {
        logger.LogDebug("Issued claims: {Claims}", (object) claims.Select(c => c.Type).ToArray());
    }
}