// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using IdentityServer4.Configuration.DependencyInjection.Options;

namespace IdentityServer4.Hosting;

class EndpointRouter : IEndpointRouter
{
    readonly IEnumerable<Endpoint> endpoints;
    readonly IdentityServerOptions options;
    readonly ILogger logger;

    public EndpointRouter(IEnumerable<Endpoint> endpoints, IdentityServerOptions options, ILogger<EndpointRouter> logger)
    {
        this.endpoints = endpoints;
        this.options = options;
        this.logger = logger;
    }

    public Option<IEndpointHandler> Find(HttpContext context) {
        var endpoint = endpoints.TryFirst(ep => context.Request.Path.Equals(ep.Path, StringComparison.OrdinalIgnoreCase));
        if (endpoint.IsSome) {
            var endpointName = endpoint.Get().Name;
            logger.LogDebug("Request path {Path} matched to endpoint type {Endpoint}", context.Request.Path, endpointName);

            return GetEndpointHandler(endpoint.Get(), context);
        }

        logger.LogTrace("No endpoint entry found for request path: {Path}", context.Request.Path);

        return None;
    }

    Option<IEndpointHandler> GetEndpointHandler(Endpoint endpoint, HttpContext context)
    {
        if (options.Endpoints.IsEndpointEnabled(endpoint))
        {
            if (context.RequestServices.GetService(endpoint.Handler) is IEndpointHandler handler)
            {
                logger.LogDebug("Endpoint enabled: {Endpoint}, successfully created handler: {EndpointHandler}", endpoint.Name, endpoint.Handler.FullName);
                return Some(handler);
            }

            logger.LogDebug("Endpoint enabled: {Endpoint}, failed to create handler: {EndpointHandler}", endpoint.Name, endpoint.Handler.FullName);
        }
        else
            logger.LogWarning("Endpoint disabled: {Endpoint}", endpoint.Name);

        return None;
    }
}