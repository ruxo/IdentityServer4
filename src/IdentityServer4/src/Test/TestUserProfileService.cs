// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Models;
using IdentityServer4.Models.Contexts;
#pragma warning disable CS1998

namespace IdentityServer4.Test;

/// <summary>
/// Profile service for test users
/// </summary>
/// <seealso cref="IdentityServer4.Services.IProfileService" />
public class TestUserProfileService : IProfileService
{
    /// <summary>
    /// The logger
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    /// The users
    /// </summary>
    protected readonly TestUserStore Users;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestUserProfileService"/> class.
    /// </summary>
    /// <param name="users">The users.</param>
    /// <param name="logger">The logger.</param>
    public TestUserProfileService(TestUserStore users, ILogger<TestUserProfileService> logger)
    {
        Users = users;
        Logger = logger;
    }

    /// <summary>
    /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public virtual async Task<IEnumerable<Claim>> GetIssuedClaims(ProfileDataRequestContext context)
    {
        context.LogProfileRequest(Logger);

        var user = Users.FindBySubjectId(context.Subject.GetSubjectId());
        var claims = user.Map(u => context.FilterClaims(u.Claims)).IfNone(Enumerable.Empty<Claim>()).ToArray();

        claims.LogIssuedClaims(Logger);

        return claims;
    }

    /// <summary>
    /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
    /// (e.g. during token issuance or validation).
    /// </summary>
    /// <returns></returns>
    public Task<bool> IsActiveAsync(ClaimsPrincipal subject, Client client, string caller)
    {
        Logger.LogDebug("IsActive called from: {Caller}", caller);

        var user = Users.FindBySubjectId(subject.GetSubjectId());

        return Task.FromResult(user.GetOrDefault(u => u.IsActive));
    }
}