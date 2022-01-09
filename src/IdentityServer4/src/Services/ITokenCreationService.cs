// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;

namespace IdentityServer4.Services;

/// <summary>
/// Logic for creating security tokens
/// </summary>
public interface ITokenCreationService
{
    /// <summary>
    /// Creates a token.
    /// </summary>
    /// <returns>A protected and serialized security token</returns>
    Task<string> CreateTokenAsync(string tokenType, IEnumerable<string> allowedSigningAlgorithms, string issuer, int lifetime, string[] audiences, Claim[] claims,
                                  Option<string> confirmation);
}