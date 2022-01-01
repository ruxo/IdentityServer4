// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation.Contexts;

/// <summary>
/// Class describing the resource owner password validation context
/// </summary>
public sealed record ResourceOwnerPasswordValidationContext(string UserName, string Password, ValidatedTokenRequest Request);