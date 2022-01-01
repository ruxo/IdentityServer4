// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Logging;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Services.Default;

/// <summary>
/// Default implementation of the event service. Write events raised to the log.
/// </summary>
public sealed class DefaultEventSink : IEventSink
{
    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultEventSink"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public DefaultEventSink(ILogger<DefaultEventSink> logger)
    {
        this.logger = logger;
    }

    /// <summary>
    /// Raises the specified event.
    /// </summary>
    /// <param name="evt">The event.</param>
    /// <exception cref="System.ArgumentNullException">evt</exception>
    public ValueTask PersistAsync(FullEvent evt)
    {
        logger.LogInformation("{@Event}", LogSerializer.Serialize(evt));
        return new();
    }
}