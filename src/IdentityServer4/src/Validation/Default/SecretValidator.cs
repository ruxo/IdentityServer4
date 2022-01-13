// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates secrets using the registered validators
/// </summary>
public sealed class SecretValidator : ISecretsListValidator
{
    readonly ILogger logger;
    readonly IEnumerable<ISecretValidator> validators;
    readonly ISystemClock clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretValidator"/> class.
    /// </summary>
    /// <param name="clock">The clock.</param>
    /// <param name="validators">The validators.</param>
    /// <param name="logger">The logger.</param>
    public SecretValidator(ISystemClock clock, IEnumerable<ISecretValidator> validators, ILogger<SecretValidator> logger)
    {
        this.clock = clock;
        this.validators = validators;
        this.logger = logger;
    }

    /// <inheritdoc />
    public Task<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials) {
        var now = clock.UtcNow.UtcDateTime;

        var (expiredSecrets, currentSecrets) = secrets.Partition(s => s.Expiration.HasExpired(now));
        expiredSecrets.Iter(ex => logger.LogInformation("Secret [{Description}] is expired", ex.Description ?? "no description"));

        // see if a registered validator can validate the secret
        return validators.ChooseAsync(validator => validator.ValidateAsync(currentSecrets, credentials))
                         .TryFirst();
    }
}