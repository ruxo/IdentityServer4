// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Immutable;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Scope type
/// </summary>
public enum ParsedScopeType
{
    /// <summary>
    /// Simple scope value
    /// </summary>
    Simple,
    /// <summary>
    /// Structure scope value
    /// </summary>
    Structure,
}

/// <summary>
/// Models a parsed scope value.
/// </summary>
/// <param name="Name">The parsed name of the scope. If the scope has no structure, the parsed name will be the same as the raw value.</param>
/// <param name="Value">The parameter value of the parsed scope. If the scope has no structure, then the value will be null.</param>
public sealed record ParsedScopeValue(ParsedScopeType Type, string Name, ImmutableDictionary<string, string> Value)
{
    /// <summary>
    /// Create a simple value
    /// </summary>
    public static ParsedScopeValue Create(string name) =>
        new (ParsedScopeType.Simple, name, ImmutableDictionary<string, string>.Empty);
}