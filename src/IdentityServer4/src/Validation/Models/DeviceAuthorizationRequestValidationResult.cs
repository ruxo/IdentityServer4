// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Validation.Models;

/// <summary>
/// Validation result for device authorization requests
/// </summary>
public sealed record DeviceAuthorizationRequestValidationResult(ValidatedDeviceAuthorizationRequest ValidatedRequest);
/// <summary>
/// Failed result
/// </summary>
public sealed record DeviceAuthorizationRequestValidationError(Option<ValidatedDeviceAuthorizationRequest> ValidatedRequest, string Error, string? ErrorDescription = null)
    : ErrorInfo(Error, ErrorDescription);