// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System.Collections.Generic;
using IdentityServer4.Validation.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.ResponseHandling;

/// <summary>
/// Models a token error response
/// </summary>
public sealed record TokenErrorResponse(Dictionary<string, object> Custom) : ErrorInfo
{
    /// <summary>
    /// Initialize empty
    /// </summary>
    public TokenErrorResponse(string error, string? errorDescription = null, Dictionary<string, object>? custom = null) : this(custom ?? new Dictionary<string, object>()) {
        ErrorDescription = errorDescription ?? "-- no message --";
    }
}