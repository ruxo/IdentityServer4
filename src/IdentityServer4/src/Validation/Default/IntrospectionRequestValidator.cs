// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// The introspection request validator
/// </summary>
/// <seealso cref="IdentityServer4.Validation.IIntrospectionRequestValidator" />
class IntrospectionRequestValidator : IIntrospectionRequestValidator
{
    readonly ILogger logger;
    readonly ITokenValidator tokenValidator;

    /// <summary>
    /// Initializes a new instance of the <see cref="IntrospectionRequestValidator"/> class.
    /// </summary>
    /// <param name="tokenValidator">The token validator.</param>
    /// <param name="logger">The logger.</param>
    public IntrospectionRequestValidator(ITokenValidator tokenValidator, ILogger<IntrospectionRequestValidator> logger)
    {
        this.tokenValidator = tokenValidator;
        this.logger = logger;
    }

    /// <summary>
    /// Validates the request.
    /// </summary>
    /// <param name="parameters">The parameters.</param>
    /// <param name="api">The API.</param>
    /// <returns></returns>
    public async Task<Either<ErrorInfo, TokenValidationResult>> ValidateAsync(Dictionary<string,string> parameters, ApiResource api)
    {
        logger.LogDebug("Introspection request validation started");

        var token = parameters.Get("token");
        if (token.IsNone)
        {
            logger.LogError("Token is missing");

            return new ErrorInfo("missing_token");
        }

        var tokenValidationResult = await tokenValidator.ValidateAccessTokenAsync(token.Get());

        if (tokenValidationResult.IsLeft)
        {
            logger.LogDebug("Token {Token} is invalid", token.Get());

            return tokenValidationResult;
        }

        logger.LogDebug("Introspection request validation successful");

        return tokenValidationResult;
    }
}