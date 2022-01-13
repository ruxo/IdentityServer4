// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using IdentityModel;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates a shared secret stored in SHA256 or SHA512
/// </summary>
public class HashedSharedSecretValidator : ISecretValidator
{
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashedSharedSecretValidator"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public HashedSharedSecretValidator(ILogger<HashedSharedSecretValidator> logger)
    {
        this.logger = logger;
    }

    /// <summary>
    /// Validates a secret
    /// </summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="credentials">The received secret.</param>
    /// <returns>
    /// A validation result
    /// </returns>
    /// <exception cref="System.ArgumentNullException">Id or cedential</exception>
    public async ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials)
    {
        if (credentials is not Credentials.Shared(_, var sharedSecret))
            return None;

        var sharedSecrets = secrets.Where(s => s.Type == IdentityServerConstants.SecretTypes.SharedSecret);
        var secretSha256 = sharedSecret.Sha256();
        var secretSha512 = sharedSecret.Sha512();

        foreach (var secret in sharedSecrets)
        {
            var secretDescription = string.IsNullOrEmpty(secret.Description) ? "no description" : secret.Description;

            byte[] secretBytes;

            try
            {
                secretBytes = Convert.FromBase64String(secret.Value);
            }
            catch (FormatException)
            {
                logger.LogError("Secret: {Description} uses invalid hashing algorithm", secretDescription);
                return None;
            }
            catch (ArgumentNullException)
            {
                logger.LogError("Secret: {Description} is null", secretDescription);
                return None;
            }

            if (secretBytes.Length == 32 && TimeConstantComparer.IsEqual(secret.Value, secretSha256)
             || secretBytes.Length == 64 && TimeConstantComparer.IsEqual(secret.Value, secretSha512))
                return new SecretInfo();
            if (secretBytes.Length is not (32 or 64))
            {
                logger.LogError("Secret: {Description} uses invalid hashing algorithm", secretDescription);
                return None;
            }
        }
        return None;
    }
}