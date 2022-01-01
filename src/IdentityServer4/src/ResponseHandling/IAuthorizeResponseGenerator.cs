// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Validation;
using IdentityServer4.ResponseHandling.Models;

namespace IdentityServer4.ResponseHandling;

// TODO Remove this!
/// <summary>
/// Interface for the authorize response generator
/// </summary>
[Obsolete]
public interface IAuthorizeResponseGenerator
{
    /// <summary>
    /// Creates the response
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    Task<AuthorizeResponse> CreateResponseAsync(ValidatedAuthorizeRequest request);
}