// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation;

/// <summary>
/// Interface for the token request validator
/// </summary>
public interface ITokenRequestValidator
{
    /// <summary>
    /// Validates the request.
    /// </summary>
    /// <param name="parameters">The parameters.</param>
    /// <param name="verifiedClient">The client validation result.</param>
    /// <returns></returns>
    Task<Either<ErrorWithCustomResponse,Unit>> ValidateRequestAsync(ApiParameters parameters, VerifiedClient verifiedClient);
}