// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;

namespace IdentityServer4.Hosting;

/// <summary>
/// IdentityServer middleware
/// </summary>
public class IdentityServerMiddleware
{
    readonly RequestDelegate next;
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityServerMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next.</param>
    /// <param name="logger">The logger.</param>
    public IdentityServerMiddleware(RequestDelegate next, ILogger<IdentityServerMiddleware> logger)
    {
        this.next = next;
        this.logger = logger;
    }

    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="router">The router.</param>
    /// <param name="session">The user session.</param>
    /// <param name="events">The event service.</param>
    /// <param name="backChannelLogoutService"></param>
    /// <returns></returns>
    public async Task Invoke(HttpContext context, IEndpointRouter router, IUserSession session, IEventService events, IBackChannelLogoutService backChannelLogoutService)
    {
        // this will check the authentication session and from it emit the check session
        // cookie needed from JS-based signout clients.
        await session.EnsureSessionIdCookieAsync();

        context.Response.OnStarting(async () =>
        {
            if (context.GetSignOutCalled())
            {
                logger.LogDebug("SignOutCalled set; processing post-signout session cleanup");

                // this clears our session id cookie so JS clients can detect the user has signed out
                await session.RemoveSessionIdCookieAsync();

                // back channel logout
                var logoutContext = await session.GetLogoutNotificationContext();
                if (logoutContext.IsSome) await backChannelLogoutService.SendLogoutNotificationsAsync(logoutContext.Get());
            }
        });

        try
        {
            var endpoint = router.Find(context);
            if (endpoint.IsSome)
            {
                logger.LogInformation("Invoking IdentityServer endpoint: {EndpointType} for {Url}", endpoint.Get().GetType().FullName, context.Request.Path.ToString());

                var result = await endpoint.Get().HandleRequest(context);
                // TODO: handle error
                return;
            }
        }
        catch (Exception ex)
        {
            await events.RaiseAsync(new UnhandledExceptionEvent(ex));
            logger.LogCritical(ex, "Unhandled exception: {Exception}", ex.Message);
            throw;
        }

        await next(context);
    }
}