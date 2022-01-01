// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;
using IdentityServer4.Models;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Models the validation result of access tokens and id tokens.
/// </summary>
public interface TokenValidationResult
{
    /// <summary>
    /// Original token
    /// </summary>
    string Token { get; }
    /// <summary>
    ///
    /// </summary>
    Client Client { get; }

    /// <summary>
    ///
    /// </summary>
    Claim[] Claims { get; }
}

/// <summary>
/// Validated access token result.
/// </summary>
/// <param name="Client"></param>
/// <param name="Claims"></param>
public abstract record ValidatedAccessToken(string Token, Client Client, Claim[] Claims) : TokenValidationResult;

/// <summary>
///
/// </summary>
/// <param name="Client"></param>
/// <param name="Claims"></param>
public sealed record ValidatedJwtAccessToken(string Token, Client Client, Claim[] Claims, string Jwt) : TokenValidationResult;

/// <summary>
///
/// </summary>
/// <param name="Client"></param>
/// <param name="Claims"></param>
/// <param name="ReferenceTokenId">the reference token identifier (in case of access token validation).</param>
/// <param name="ReferenceToken">the refresh token (in case of refresh token validation).</param>
public sealed record ValidatedReferenceAccessToken(string Token, Client Client, Claim[] Claims, Token ReferenceToken, string ReferenceTokenId) : TokenValidationResult;