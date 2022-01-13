// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;

namespace IdentityServer4.Validation;

/// <summary>
///
/// </summary>
/// <param name="Confirmation"></param>
public readonly record struct SecretInfo(Option<string> Confirmation);

/// <summary>
/// Service for validating a received secret against a stored secret
/// </summary>
public interface ISecretValidator
{
    /// <summary>
    /// Validates a secret
    /// </summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="credentials">The received secret.</param>
    /// <returns>A validation result</returns>
    ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials);
}