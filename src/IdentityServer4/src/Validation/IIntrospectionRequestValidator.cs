// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation;

/// <summary>
/// Interface for the introspection request validator
/// </summary>
public interface IIntrospectionRequestValidator
{
    /// <summary>
    /// Validates the request.
    /// </summary>
    /// <param name="parameters">The parameters.</param>
    /// <param name="api">The API.</param>
    /// <returns></returns>
    Task<Either<ErrorInfo, TokenValidationResult>> ValidateAsync(Dictionary<string,string> parameters, ApiResource api);
}