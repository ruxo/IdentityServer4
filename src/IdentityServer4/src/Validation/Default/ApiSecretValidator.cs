// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates API secrets using the registered secret validators and parsers
/// </summary>
public class ApiSecretValidator : IApiSecretValidator
{
    readonly ILogger logger;
    readonly IResourceStore resources;
    readonly IEventService events;
    readonly ISecretsListParser parser;
    readonly ISecretsListValidator validator;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiSecretValidator"/> class.
    /// </summary>
    /// <param name="resources">The resources.</param>
    /// <param name="parsers">The parsers.</param>
    /// <param name="validator">The validator.</param>
    /// <param name="events">The events.</param>
    /// <param name="logger">The logger.</param>
    public ApiSecretValidator(IResourceStore resources, ISecretsListParser parsers, ISecretsListValidator validator, IEventService events, ILogger<ApiSecretValidator> logger)
    {
        this.resources = resources;
        parser = parsers;
        this.validator = validator;
        this.events = events;
        this.logger = logger;
    }

    /// <summary>
    /// Validates the secret on the current request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public async Task<Either<ErrorInfo, ApiResource>> ValidateAsync(HttpContext context)
    {
        logger.LogTrace("Start API validation");

        var parsedSecret = await parser.GetCredentials(context);
        if (parsedSecret.IsNone)
        {
            await RaiseFailureEventAsync("unknown", "No API id or secret found");

            logger.LogError("No API secret found");
            return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
        }
        var secretId = parsedSecret.Get().ClientId;

        // load API resource
        var apis = Seq(await resources.FindApiResourcesByNameAsync(new[] { secretId }));
        if (!apis.Any())
        {
            await RaiseFailureEventAsync(secretId, "Unknown API resource");

            logger.LogError("No API resource with that name found. aborting");
            return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
        }

        if (apis.Count() > 1)
        {
            await RaiseFailureEventAsync(secretId, "Invalid API resource");

            logger.LogError("More than one API resource with that name found. aborting");
            return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
        }

        var api = apis.Single();

        if (api.Enabled == false)
        {
            await RaiseFailureEventAsync(secretId, "API resource not enabled");

            logger.LogError("API resource not enabled. aborting");
            return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
        }

        var result = await validator.ValidateAsync(api.ApiSecrets, parsedSecret.Get());
        if (result.Success)
        {
            logger.LogDebug("API resource validation success");

            await RaiseSuccessEventAsync(api.Name, parsedSecret.Get().Type);
            return api;
        }

        await RaiseFailureEventAsync(api.Name, "Invalid API secret");
        logger.LogError("API validation failed");

        return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
    }

    Task RaiseSuccessEventAsync(string clientId, string authMethod) => events.RaiseAsync(ApiAuthenticationSuccessEvent.Create(clientId, authMethod));

    Task RaiseFailureEventAsync(string clientId, string message) => events.RaiseAsync(ApiAuthenticationFailureEvent.Create(clientId, message));
}