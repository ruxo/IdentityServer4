// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Validation.Models;
#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default custom token validator
/// </summary>
public sealed class DefaultCustomTokenValidator : ICustomTokenValidator
{
    /// <inheritdoc />
    public async Task<Option<ErrorInfo>> ValidateAccessTokenAsync(string token, TokenValidationResult result)
    {
        return None;
    }

    /// <inheritdoc />
    public async Task<Option<ErrorInfo>> ValidateIdentityTokenAsync(string token, ValidatedJwtAccessToken result)
    {
        return None;
    }
}