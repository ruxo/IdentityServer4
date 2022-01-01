// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Diagnostics;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Events;
using IdentityServer4.Events.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.Services.Default;

/// <summary>
/// The default event service
/// </summary>
/// <seealso cref="IdentityServer4.Services.IEventService" />
public sealed class DefaultEventService : IEventService
{
    /// <summary>
    /// The options
    /// </summary>
    readonly IdentityServerOptions options;

    /// <summary>
    /// The context
    /// </summary>
    readonly IHttpContextAccessor context;

    /// <summary>
    /// The sink
    /// </summary>
    readonly IEventSink sink;

    /// <summary>
    /// The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultEventService"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="context">The context.</param>
    /// <param name="sink">The sink.</param>
    /// <param name="clock">The clock.</param>
    public DefaultEventService(IdentityServerOptions options, IHttpContextAccessor context, IEventSink sink, ISystemClock clock)
    {
        this.options = options;
        this.context = context;
        this.sink    = sink;
        this.clock   = clock;
    }

    /// <summary>
    /// Raises the specified event.
    /// </summary>
    /// <param name="evt">The event.</param>
    /// <returns></returns>
    /// <exception cref="System.ArgumentNullException">evt</exception>
    public async Task RaiseAsync(Event evt)
    {
        if (CanRaiseEvent(evt)) await sink.PersistAsync(PrepareEventAsync(evt));
    }

    /// <summary>
    /// Indicates if the type of event will be persisted.
    /// </summary>
    /// <param name="evtType"></param>
    /// <returns></returns>
    /// <exception cref="System.ArgumentOutOfRangeException"></exception>
    public bool CanRaiseEventType(EventTypes evtType) =>
        evtType switch{
            EventTypes.Failure     => options.Events.RaiseFailureEvents,
            EventTypes.Information => options.Events.RaiseInformationEvents,
            EventTypes.Success     => options.Events.RaiseSuccessEvents,
            EventTypes.Error       => options.Events.RaiseErrorEvents,
            _                      => throw new ArgumentOutOfRangeException(nameof(evtType))
        };

    /// <summary>
    /// Determines whether this event would be persisted.
    /// </summary>
    /// <param name="evt">The evt.</param>
    /// <returns>
    ///   <c>true</c> if this event would be persisted; otherwise, <c>false</c>.
    /// </returns>
    bool CanRaiseEvent(Event evt) => CanRaiseEventType(evt.Type);

    /// <summary>
    /// Prepares the event.
    /// </summary>
    /// <param name="evt">The evt.</param>
    /// <returns></returns>
    FullEvent PrepareEventAsync(Event evt) {
        var ctx = context.HttpContext!;
        return new(evt,
                   ctx.TraceIdentifier,
                   clock.UtcNow.UtcDateTime,
                   Process.GetCurrentProcess().Id,
                   ctx.Connection.LocalIpAddress != null ? $"{ctx.Connection.LocalIpAddress}:{ctx.Connection.LocalPort}" : "unknown",
                   ctx.Connection.RemoteIpAddress != null ? ctx.Connection.RemoteIpAddress.ToString() : "unknown");
    }
}