// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.ResponseHandling;

/// <summary>
///
/// </summary>
/// <param name="IsActive"></param>
/// <param name="Scopes"></param>
public sealed record IntrospectionResponse(string Scope, Dictionary<string, object[]> Claims);

/// <summary>
/// Interface for introspection response generator
/// </summary>
public interface IIntrospectionResponseGenerator
{
    /// <summary>
    /// Processes the response.
    /// </summary>
    /// <param name="api"></param>
    /// <param name="validationResult">The validation result.</param>
    /// <returns></returns>
    Task<Option<IntrospectionResponse>> ProcessAsync(ApiResource api, TokenValidationResult validationResult);
}