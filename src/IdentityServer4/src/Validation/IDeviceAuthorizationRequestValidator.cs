// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Specialized;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation;

/// <summary>
///  Device authorization endpoint request validator.
/// </summary>
public interface IDeviceAuthorizationRequestValidator
{
    /// <summary>
    ///  Validates authorize request parameters.
    /// </summary>
    /// <param name="parameters"></param>
    /// <param name="verifiedClientValidationResult"></param>
    /// <returns></returns>
    Task<Either<DeviceAuthorizationRequestValidationError, DeviceAuthorizationRequestValidationResult>> ValidateAsync(Dictionary<string,string> parameters, VerifiedClient verifiedClientValidationResult);
}