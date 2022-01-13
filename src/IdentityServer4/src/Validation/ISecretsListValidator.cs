// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.
using IdentityServer4.Models;

namespace IdentityServer4.Validation;

/// <summary>
/// Validator for an Enumerable List of Secrets
/// </summary>
public interface ISecretsListValidator
{
    /// <summary>
    /// Validates a list of secrets
    /// </summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="credentials">The received secret.</param>
    /// <returns>Gets or sets the value of the confirmation method (will become the cnf claim). Must be a JSON object.</returns>
    Task<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials);
}