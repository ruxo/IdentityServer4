// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation;

/// <summary>
/// The device code validator
/// </summary>
public interface IDeviceCodeValidator
{
    /// <summary>
    /// Validates the device code.
    /// </summary>
    Task<Either<ErrorWithCustomResponse, Unit>> ValidateAsync(Client client, string deviceCode);
}