// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models.Contexts;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default custom request validator
/// </summary>
sealed class DefaultCustomAuthorizeRequestValidator : ICustomAuthorizeRequestValidator
{
    /// <summary>
    /// Custom validation logic for the authorize request.
    /// </summary>
    /// <param name="context">The context.</param>
    public ValueTask<AuthContext> ValidateAsync(AuthContext context) => ValueTask.FromResult(context);
}