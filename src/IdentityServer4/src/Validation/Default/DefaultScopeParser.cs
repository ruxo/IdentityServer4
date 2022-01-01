// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default implementation of IScopeParser.
/// </summary>
public sealed class DefaultScopeParser : IScopeParser
{
    /// <inheritdoc/>
    public (ParsedScopeValue[] Scopes, ParsedScopeValidationError[] FailedScopes) ParseScopeValues(IEnumerable<string> scopeValues)
    {
        // TODO: handle structured scopes?
        return (scopeValues.Map(ParsedScopeValue.Create).ToArray(), Array.Empty<ParsedScopeValidationError>());
    }
}