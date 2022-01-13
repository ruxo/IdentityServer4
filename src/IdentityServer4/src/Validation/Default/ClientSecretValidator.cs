// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Services;
using IdentityServer4.Events;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using IdentityServer4.Stores;
using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Validates a client secret using the registered secret validators and parsers
/// </summary>
public class ClientSecretValidator : IClientSecretValidator
{
    readonly ILogger logger;
    readonly IClientStore clients;
    readonly IEventService events;
    readonly ISecretsListValidator validator;
    readonly ISecretsListParser parser;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClientSecretValidator"/> class.
    /// </summary>
    /// <param name="clients">The clients.</param>
    /// <param name="parser">The parser.</param>
    /// <param name="validator">The validator.</param>
    /// <param name="events">The events.</param>
    /// <param name="logger">The logger.</param>
    public ClientSecretValidator(IClientStore clients, ISecretsListParser parser, ISecretsListValidator validator, IEventService events, ILogger<ClientSecretValidator> logger)
    {
        this.clients   = clients;
        this.parser    = parser;
        this.validator = validator;
        this.events    = events;
        this.logger    = logger;
    }

    /// <summary>
    /// Validates the current request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public async Task<Either<ErrorInfo,VerifiedClient>> GetVerifiedClient(HttpContext context)
    {
        logger.LogDebug("Start client validation");

        var ps = await parser.GetCredentials(context);
        if (ps.IsNone)
        {
            await RaiseFailureEventAsync("unknown", "No client id found");

            logger.LogError("No client identifier found");
            return new ErrorInfo();
        }
        var credentials = ps.Get();

        // load client
        var clientOpt = await clients.FindEnabledClientByIdAsync(credentials.ClientId);
        if (clientOpt.IsNone)
        {
            await RaiseFailureEventAsync(credentials.ClientId, "Unknown client");

            logger.LogError("No client with id '{ClientId}' found. aborting", credentials.ClientId);
            return new ErrorInfo();
        }
        var client = clientOpt.Get();

        Option<SecretInfo> secretValidationResult = None;
        if (!client.RequireClientSecret || client.IsImplicitOnly())
            logger.LogDebug("Public Client - skipping secret validation success");
        else {
            secretValidationResult = await validator.ValidateAsync(client.ClientSecrets, credentials);
            if (!secretValidationResult.IsSome)
            {
                await RaiseFailureEventAsync(client.ClientId, "Invalid client secret");
                logger.LogError("Client secret validation failed for client: {ClientId}", client.ClientId);

                return new ErrorInfo();
            }
        }

        logger.LogDebug("Client validation success");

        await RaiseSuccessEventAsync(client.ClientId, credentials.Secret.Type);
        return new VerifiedClient(client, credentials.Secret, secretValidationResult.Bind(r => r.Confirmation));
    }

    Task RaiseSuccessEventAsync(string clientId, string authMethod) => events.RaiseAsync(new ClientAuthenticationSuccessEvent(clientId, authMethod));

    Task RaiseFailureEventAsync(string clientId, string message) => events.RaiseAsync(new ClientAuthenticationFailureEvent(clientId, message));
}