// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Net.Http;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Services.Default;

/// <summary>
/// Default JwtRequest client
/// </summary>
public class DefaultJwtRequestUriHttpClient : IJwtRequestUriHttpClient
{
    readonly HttpClient http;
    readonly IdentityServerOptions options;
    readonly ILogger logger;

    /// <summary>
    /// ctor
    /// </summary>
    public DefaultJwtRequestUriHttpClient(HttpClient http, IdentityServerOptions options, ILogger<DefaultJwtRequestUriHttpClient> logger)
    {
        this.http = http;
        this.options = options;
        this.logger = logger;
    }


    /// <inheritdoc />
    public async Task<Option<string>> GetJwtAsync(string url, Client client)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        // req.Properties.Add(IdentityServerConstants.JwtRequestClientKey, client);
        req.Options.Set(new(IdentityServerConstants.JwtRequestClientKey), client);

        var response = await http.SendAsync(req);
        if (response.IsSuccessStatusCode)
        {
            if (options.StrictJarValidation &&
                !$"application/{JwtClaimTypes.JwtTypes.AuthorizationRequest}".Equals(response.Content.Headers.ContentType!.MediaType, StringComparison.Ordinal)) {
                logger.LogError("Invalid content type {Type} from jwt url {Url}", response.Content.Headers.ContentType.MediaType, url);
                return None;
            }

            logger.LogDebug("Success http response from jwt url {Url}", url);

            return await response.Content.ReadAsStringAsync();
        }

        logger.LogError("Invalid http status code {Status} from jwt url {Url}", response.StatusCode, url);
        return None;
    }
}