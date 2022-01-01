// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Security.Claims;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation;

/// <summary>
///  Authorize endpoint request validator.
/// </summary>
[Obsolete]
public interface IAuthorizeRequestValidator
{
    /// <summary>
    /// Validates authorized request parameters without principal.
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    Task<Either<ErrorInfo, AuthorizeRequestValidationResult>> ValidateAsync(Dictionary<string,string> parameters) => ValidateAsync(parameters, None);

    /// <summary>
    ///  Validates authorize request parameters.
    /// </summary>
    /// <param name="parameters"></param>
    /// <param name="subject"></param>
    /// <returns></returns>
    Task<Either<ErrorInfo, AuthorizeRequestValidationResult>> ValidateAsync(Dictionary<string,string> parameters, Option<ClaimsPrincipal> subject);
}