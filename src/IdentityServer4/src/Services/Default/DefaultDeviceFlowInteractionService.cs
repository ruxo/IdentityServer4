// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.Extensions.Logging;

// ReSharper disable CheckNamespace

namespace IdentityServer4.Services;

class DefaultDeviceFlowInteractionService : IDeviceFlowInteractionService
{
    readonly IClientStore _clients;
    readonly IUserSession _session;
    readonly IDeviceFlowCodeService _devices;
    readonly IResourceStore _resourceStore;
    readonly IScopeParser _scopeParser;
    readonly ILogger<DefaultDeviceFlowInteractionService> _logger;

    public DefaultDeviceFlowInteractionService(
        IClientStore                                 clients,
        IUserSession                                 session,
        IDeviceFlowCodeService                       devices,
        IResourceStore                               resourceStore,
        IScopeParser                                 scopeParser,
        ILogger<DefaultDeviceFlowInteractionService> logger)
    {
        _clients       = clients;
        _session       = session;
        _devices       = devices;
        _resourceStore = resourceStore;
        _scopeParser   = scopeParser;
        _logger        = logger;
    }

    public Task<Option<DeviceFlowAuthorizationRequest>> GetAuthorizationContextAsync(string userCode)
    {
        async Task<DeviceFlowAuthorizationRequest> getRequest(DeviceCode deviceAuth, Client client)
        {
            var parsedScopesResult = _scopeParser.ParseScopeValues(deviceAuth.RequestedScopes);
            var validatedResources = await _resourceStore.FindAllResources(parsedScopesResult);

            return new()
            {
                Client             = client,
                ValidatedResources = validatedResources
            };
        }

        return _devices.FindByUserCodeAsync(userCode)
                       .BindT(da => _clients.FindClientByIdAsync(da.ClientId).MapT(client => getRequest(da, client)));
    }

    public async Task<DeviceFlowInteractionResult> HandleRequestAsync(string userCode, ConsentResponse consent) {
        if (userCode == null) throw new ArgumentNullException(nameof(userCode));
        if (consent == null) throw new ArgumentNullException(nameof(consent));

        var da = await _devices.FindByUserCodeAsync(userCode);
        if (da.IsNone) return LogAndReturnError("Invalid user code", "Device authorization failure - user code is invalid");
        var deviceAuth = da.Get();

        var client = await _clients.FindClientByIdAsync(deviceAuth.ClientId);
        if (client.IsNone) return LogAndReturnError("Invalid client", "Device authorization failure - requesting client is invalid");

        var subject = await _session.GetUserAsync();
        if (subject.IsNone) return LogAndReturnError("No user present in device flow request", "Device authorization failure - no user found");

        var sid = await _session.GetSessionIdAsync();

        deviceAuth.IsAuthorized       = true;
        deviceAuth.Subject            = subject.Get();
        deviceAuth.SessionId          = sid.Get();
        deviceAuth.ConsentDescription = consent.Description;
        deviceAuth.AuthorizedScopes   = consent.ScopesValuesConsented;

        // TODO: Device Flow - Record consent template
        if (consent.RememberConsent) {
            //var consentRequest = new ConsentRequest(request, subject);
            //await _consentMessageStore.WriteAsync(consentRequest.Id, new Message<ConsentResponse>(consent, _clock.UtcNow.UtcDateTime));
        }

        await _devices.UpdateByUserCodeAsync(userCode, deviceAuth);

        return new();
    }

    DeviceFlowInteractionResult LogAndReturnError(string error, string? errorDescription = null)
    {
        // ReSharper disable once TemplateIsNotCompileTimeConstantProblem
        if (errorDescription != null) _logger.LogError(errorDescription);
        return DeviceFlowInteractionResult.Failure(error);
    }
}