// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Models;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.Services;

/// <summary>
/// Interface for the key material service
/// </summary>
public interface IKeyMaterialService
{
    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    IAsyncEnumerable<SecurityKeyInfo> GetValidationKeysAsync();

    /// <summary>
    /// Gets the signing credentials.
    /// </summary>
    /// <param name="allowedAlgorithms">Collection of algorithms used to filter the server supported algorithms.
    /// A value of null or empty indicates that the server default should be returned.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException">No credential found</exception>
    Task<SigningCredentials> GetSigningCredentialsAsync(IEnumerable<string> allowedAlgorithms);

    /// <summary>
    /// Get the signing credential's algorithm.
    /// </summary>
    /// <param name="allowedAlgorithms">Collection of algorithms used to filter the server supported algorithms.
    /// A value of empty indicates that the server default should be returned.</param>
    /// <returns></returns>
    Task<string> GetSigningAlgorithm(IEnumerable<string> allowedAlgorithms);

    /// <summary>
    /// Gets all signing credentials.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<SigningCredentials>> GetAllSigningCredentialsAsync();
}