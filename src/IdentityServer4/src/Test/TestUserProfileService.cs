// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Services;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Models;
#pragma warning disable CS1998

namespace IdentityServer4.Test;

/// <summary>
/// Profile service for test users
/// </summary>
/// <seealso cref="IdentityServer4.Services.IProfileService" />
public class TestUserProfileService : IProfileService
{
    /// <summary>
    /// The users
    /// </summary>
    protected readonly TestUserStore Users;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestUserProfileService"/> class.
    /// </summary>
    /// <param name="users">The users.</param>
    public TestUserProfileService(TestUserStore users)
    {
        Users = users;
    }

    /// <summary>
    /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
    /// </summary>
    /// <returns></returns>
    public virtual async Task<IEnumerable<Claim>> GetIssuedClaims(IEnumerable<string> allowedClaims, UserSession session) =>
        session.SessionId
               .Bind(Users.FindBySubjectId)
               .Map(u => u.Claims.IntersectBy(allowedClaims, c => c.Type))
               .IfNone(Enumerable.Empty<Claim>())
               .ToArray();

    /// <summary>
    /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
    /// (e.g. during token issuance or validation).
    /// </summary>
    /// <returns></returns>
    public Task<bool> IsActiveAsync(ClaimsPrincipal subject, Client client)
    {
        var user = subject.GetSubjectId().Bind(Users.FindBySubjectId);
        return Task.FromResult(user.GetOrDefault(u => u.IsActive));
    }
}