// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Validation.Models;
using IdentityServer4.Extensions;

namespace IdentityServer4.Events;

/// <summary>
/// Event for device authorization failure
/// </summary>
public static class DeviceAuthorizationFailureEvent
{
    /// <summary>
    /// Create a default device authorization failure event.
    /// </summary>
    /// <returns></returns>
    public static Event Create() =>
        new(EventCategories.DeviceFlow,
            "Device Authorization Failure",
            EventTypes.Failure,
            EventIds.DeviceAuthorizationFailure,
            None);

    /// <summary>
    /// Create a default device authorization failure event.
    /// </summary>
    public static Event Create(DeviceAuthorizationRequestValidationError result) {
        var client = result.ValidatedRequest.Bind(r => r.ValidatedClient).Map(c => c.Client);
        return Create() with{
            AdditionalData = new{
                ClientId   = client.GetOrDefault(c => c.ClientId),
                ClientName = client.GetOrDefault(c => c.ClientName),
                Scopes     = result.ValidatedRequest.GetOrDefault(r => r.RequestedScopes.ToSpaceSeparatedString()),
                Endpoint   = Constants.EndpointNames.DeviceAuthorization,
                result.Error,
                result.ErrorDescription
            }
        };
    }
}