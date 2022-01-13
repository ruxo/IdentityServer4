// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityModel;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;

#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates a secret stored in plain text
/// </summary>
public class PlainTextSharedSecretValidator : ISecretValidator
{
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PlainTextSharedSecretValidator"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public PlainTextSharedSecretValidator(ILogger<PlainTextSharedSecretValidator> logger)
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
    /// <exception cref="System.ArgumentException">id or credential is missing.</exception>
    public async ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials)
    {
        if (credentials is not Credentials.Shared(_, var sharedSecret))
            return None;

        var sharedSecrets = secrets.Where(s => s.Type == IdentityServerConstants.SecretTypes.SharedSecret).ToArray();
        if (sharedSecrets.Any(secret => TimeConstantComparer.IsEqual(sharedSecret, secret.Value)))
            return new SecretInfo();

        logger.LogDebug("No matching plain text secret found");
        return None;
    }
}