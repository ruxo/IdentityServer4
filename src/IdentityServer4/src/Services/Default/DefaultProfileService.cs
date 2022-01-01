// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using System.Security.Claims;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Models.Contexts;
using Microsoft.Extensions.Logging;
#pragma warning disable CS1998

namespace IdentityServer4.Services.Default;

/// <summary>
/// Default profile service implementation.
/// This implementation sources all claims from the current subject (e.g. the cookie).
/// </summary>
/// <seealso cref="IdentityServer4.Services.IProfileService" />
public sealed class DefaultProfileService : IProfileService
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultProfileService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public DefaultProfileService(ILogger<DefaultProfileService> logger)
    {
        this.logger = logger;
    }

    /// <summary>
    /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public async Task<IEnumerable<Claim>> GetIssuedClaims(ProfileDataRequestContext context)
    {
        context.LogProfileRequest(logger);
        var result = context.FilterClaims(context.Subject.Claims).ToArray();
        result.LogIssuedClaims(logger);
        return result;
    }

    /// <summary>
    /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
    /// (e.g. during token issuance or validation).
    /// </summary>
    /// <returns></returns>
    public Task<bool> IsActiveAsync(ClaimsPrincipal subject, Client client, string caller)
    {
        logger.LogDebug("IsActive called from: {Caller}", caller);
        return Task.FromResult(true);
    }
}