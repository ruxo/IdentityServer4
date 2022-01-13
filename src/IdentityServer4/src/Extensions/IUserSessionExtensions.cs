// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityServer4.Models.Contexts;
using IdentityServer4.Services;

namespace IdentityServer4.Extensions;

/// <summary>
/// Extension for IUserSession.
/// </summary>
public static class IUserSessionExtensions
{
    /// <summary>
    /// Creates a LogoutNotificationContext for the current user session.
    /// </summary>
    /// <returns></returns>
    public static async Task<Option<LogoutNotificationContext>> GetLogoutNotificationContext(this IUserSession session) {
        var clientIds = (await session.GetClientListAsync(TODO)).ToArray();

        if (clientIds.Any())
        {
            var user = await session.GetUserAsync();
            var sub = user.Get().GetSubjectId();
            var sid = await session.GetSessionIdAsync();

            return new LogoutNotificationContext(sub, sid, clientIds);
        }
        return None;
    }
}