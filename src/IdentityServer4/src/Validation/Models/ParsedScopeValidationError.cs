// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Validation.Models;

/// <summary>
/// Models an error parsing a scope.
/// </summary>
public sealed record ParsedScopeValidationError(string Scope, string Reason);