// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using IdentityServer4.Models;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates an extension grant request using the registered validators
/// </summary>
public class ExtensionGrantValidator
{
    readonly ILogger logger;
    readonly IExtensionGrantValidator[] validators;

    /// <summary>
    /// Initializes a new instance of the <see cref="ExtensionGrantValidator"/> class.
    /// </summary>
    /// <param name="validators">The validators.</param>
    /// <param name="logger">The logger.</param>
    public ExtensionGrantValidator(IEnumerable<IExtensionGrantValidator> validators, ILogger<ExtensionGrantValidator> logger)
    {
        this.validators = validators.AsArray();
        this.logger = logger;
    }

    /// <summary>
    /// Gets the available grant types.
    /// </summary>
    /// <returns></returns>
    public IEnumerable<string> GetAvailableGrantTypes() => validators.Select(v => v.GrantType);

    /// <summary>
    /// Validates the request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns></returns>
    public async Task<Either<GrantValidationError, GrantValidationResult>> ValidateAsync(ValidatedTokenRequest request)
    {
        var validator = validators.FirstOrDefault(v => v.GrantType.Equals(request.GrantType, StringComparison.Ordinal));

        if (validator == null)
        {
            logger.LogError("No validator found for grant type");
            return GrantValidationError.Create(TokenRequestErrors.UnsupportedGrantType);
        }

        try
        {
            logger.LogTrace("Calling into custom grant validator: {Type}", validator.GetType().FullName);

            return await validator.ValidateAsync(request);
        }
        catch (Exception e)
        {
            logger.LogError(1, e, "Grant validation error: {Message}", e.Message);
            return GrantValidationError.Create(TokenRequestErrors.InvalidGrant);
        }
    }
}