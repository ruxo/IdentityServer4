// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Validation.Models;
#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default custom request validator
/// </summary>
class DefaultCustomTokenRequestValidator : ICustomTokenRequestValidator
{
    /// <summary>
    /// Custom validation logic for a token request.
    /// </summary>
    /// <returns>
    /// The validation result
    /// </returns>
    public async Task<Either<ErrorWithCustomResponse, Unit>> ValidateAsync(ValidatedTokenRequest request) => Unit.Default;
}