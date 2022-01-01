// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using IdentityServer4.Models;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Result of validation of requested scopes and resource indicators.
/// </summary>
[Obsolete]
public class ResourceValidationResult
{
    /// <summary>
    /// Ctor
    /// </summary>
    public ResourceValidationResult()
    {
    }

    /// <summary>
    /// Ctor
    /// </summary>
    /// <param name="resources"></param>
    public ResourceValidationResult(Resources resources)
    {
        Resources    = resources;
        ParsedScopes = resources.ToScopeNames().Select(x => new ParsedScopeValue(x)).ToArray();
    }

    /// <summary>
    /// Ctor
    /// </summary>
    /// <param name="resources"></param>
    /// <param name="parsedScopeValues"></param>
    public ResourceValidationResult(Resources resources, IEnumerable<ParsedScopeValue> parsedScopeValues)
    {
        Resources    = resources;
        ParsedScopes = parsedScopeValues.ToArray();
    }

    /// <summary>
    /// Indicates if the result was successful.
    /// </summary>
    public bool Succeeded => ParsedScopes.Any() && !InvalidScopes.Any();

    /// <summary>
    /// The resources of the result.
    /// </summary>
    public Resources Resources { get; set; } = new();

    /// <summary>
    /// The parsed scopes represented by the result.
    /// </summary>
    public ParsedScopeValue[] ParsedScopes { get; set; } = Array.Empty<ParsedScopeValue>();

    /// <summary>
    /// The original (raw) scope values represented by the validated result.
    /// </summary>
    public IEnumerable<string> RawScopeValues => ParsedScopes.Select(x => x.RawValue);

    /// <summary>
    /// The requested scopes that are invalid.
    /// </summary>
    public string[] InvalidScopes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Returns new result filted by the scope values.
    /// </summary>
    /// <param name="scopeValues"></param>
    /// <returns></returns>
    public ResourceValidationResult Filter(IEnumerable<string> scopeValues) {
        var sv = Seq(scopeValues);
        var offline = sv.Contains(IdentityServerConstants.StandardScopes.OfflineAccess);

        var parsedScopesToKeep = ParsedScopes.Where(x => sv.Contains(x.RawValue)).ToArray();
        var parsedScopeNamesToKeep = parsedScopesToKeep.Select(x => x.ParsedName).ToArray();

        var identityToKeep = Resources.IdentityResources.Where(x => parsedScopeNamesToKeep.Contains(x.Name));
        var apiScopesToKeep = Seq(Resources.ApiScopes.Where(x => parsedScopeNamesToKeep.Contains(x.Name)));

        var apiScopesNamesToKeep = apiScopesToKeep.Select(x => x.Name);
        var apiResourcesToKeep = Resources.ApiResources.Where(x => x.Scopes.Any(y => apiScopesNamesToKeep.Contains(y)));

        var resources = new Resources(identityToKeep, apiResourcesToKeep, apiScopesToKeep)
        {
            OfflineAccess = offline
        };

        return new()
        {
            Resources    = resources,
            ParsedScopes = parsedScopesToKeep
        };
    }
}