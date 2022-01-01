// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Validates an incoming token request using the device flow
/// </summary>
class DeviceCodeValidator : IDeviceCodeValidator
{
    readonly IDeviceFlowCodeService _devices;
    readonly IProfileService _profile;
    readonly IDeviceFlowThrottlingService _throttlingService;
    readonly ISystemClock _systemClock;
    readonly ILogger<DeviceCodeValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeviceCodeValidator"/> class.
    /// </summary>
    /// <param name="devices">The devices.</param>
    /// <param name="profile">The profile.</param>
    /// <param name="throttlingService">The throttling service.</param>
    /// <param name="systemClock">The system clock.</param>
    /// <param name="logger">The logger.</param>
    public DeviceCodeValidator(
        IDeviceFlowCodeService       devices,
        IProfileService              profile,
        IDeviceFlowThrottlingService throttlingService,
        ISystemClock                 systemClock,
        ILogger<DeviceCodeValidator> logger)
    {
        _devices           = devices;
        _profile           = profile;
        _throttlingService = throttlingService;
        _systemClock       = systemClock;
        _logger            = logger;
    }

    public async Task<Either<ErrorWithCustomResponse, Unit>> ValidateAsync(Client client, string deviceCode) {
        var dc = await _devices.FindByDeviceCodeAsync(deviceCode);

        if (dc.IsNone)
        {
            _logger.LogError("Invalid device code");
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.InvalidGrant);
        }
        var deviceInstance = dc.Get();

        // validate client binding
        if (deviceInstance.ClientId != client.ClientId)
        {
            _logger.LogError("Client {ClientId} is trying to use a device code from client {DeviceClientId}", client.ClientId, deviceInstance.ClientId);
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (await _throttlingService.ShouldSlowDown(deviceCode, deviceInstance))
        {
            _logger.LogError("Client {DeviceClientId} is polling too fast", deviceInstance.ClientId);
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.SlowDown);
        }

        // validate lifetime
        if (deviceInstance.CreationTime.AddSeconds(deviceInstance.Lifetime) < _systemClock.UtcNow)
        {
            _logger.LogError("Expired device code");
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.ExpiredToken);
        }

        // denied
        if (deviceInstance.IsAuthorized && !deviceInstance.AuthorizedScopes.Any())
        {
            _logger.LogError("No scopes authorized for device authorization. Access denied");
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.AccessDenied);
        }

        // make sure code is authorized
        if (deviceInstance.Subject.IsNone)
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.AuthorizationPending);
        var subject = deviceInstance.Subject.Get();

        // make sure user is enabled
        var isActive = await _profile.IsActiveAsync(subject, client, IdentityServerConstants.ProfileIsActiveCallers.DeviceCodeValidation);
        if (!isActive)
        {
            _logger.LogError("User has been disabled: {SubjectId}", subject.GetSubjectId());
            return ErrorWithCustomResponse.Create(OidcConstants.TokenErrors.InvalidGrant);
        }

        await _devices.RemoveByDeviceCodeAsync(deviceCode);
        return Unit.Default;
    }
}