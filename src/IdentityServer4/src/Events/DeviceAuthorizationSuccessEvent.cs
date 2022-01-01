// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Extensions;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Events;

/// <summary>
/// Event for device authorization failure
/// </summary>
/// <seealso cref="Event" />
public static class DeviceAuthorizationSuccessEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DeviceAuthorizationSuccessEvent"/> class.
    /// </summary>
    /// <param name="request">The request.</param>
    public static Event Create(DeviceAuthorizationRequestValidationResult request) {
        var client = request.ValidatedRequest.ValidatedClient.Map(c => c.Client);
        return new(EventCategories.DeviceFlow,
                   "Device Authorization Success",
                   EventTypes.Success,
                   EventIds.DeviceAuthorizationSuccess,
                   new{
                       ClientId   = client.GetOrDefault(c => c.ClientId),
                       ClientName = client.GetOrDefault(c => c.ClientName),
                       Endpoint   = Constants.EndpointNames.DeviceAuthorization,
                       Scopes     = request.ValidatedRequest.ValidatedResources.RawScopeValues.ToSpaceSeparatedString()
                   });
    }
}