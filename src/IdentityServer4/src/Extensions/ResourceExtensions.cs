// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using IdentityServer4.Validation;
using static LanguageExt.Prelude;

namespace IdentityServer4.Models;

/// <summary>
/// Extensions for Resource
/// </summary>
public static class ResourceExtensions
{
    /// <summary>
    /// Returns the collection of scope values that are required.
    /// </summary>
    /// <param name="resourceValidationResult"></param>
    /// <returns></returns>
    public static IEnumerable<string> GetRequiredScopeValues(this ResourceValidationResult resourceValidationResult)
    {
        var names = resourceValidationResult.Resources.IdentityResources.Where(x => x.Required).Select(x => x.Name).ToList();
        names.AddRange(resourceValidationResult.Resources.ApiScopes.Where(x => x.Required).Select(x => x.Name));

        var values = resourceValidationResult.ParsedScopes.Where(x => names.Contains(x.ParsedName)).Select(x => x.RawValue);
        return values;
    }

    /// <summary>
    /// Converts to scope names.
    /// </summary>
    /// <param name="resources">The resources.</param>
    /// <returns></returns>
    public static IEnumerable<string> ToScopeNames(this Resources resources)
    {
        var names = resources.IdentityResources.Select(x => x.Name).ToList();
        names.AddRange(resources.ApiScopes.Select(x => x.Name));
        if (resources.OfflineAccess)
        {
            names.Add(IdentityServerConstants.StandardScopes.OfflineAccess);
        }

        return names;
    }

    /// <summary>
    /// Finds the IdentityResource that matches the scope.
    /// </summary>
    /// <param name="resources">The resources.</param>
    /// <param name="name">The name.</param>
    /// <returns></returns>
    public static IdentityResource FindIdentityResourcesByScope(this Resources resources, string name)
    {
        var q = from id in resources.IdentityResources
                where id.Name == name
                select id;
        return q.FirstOrDefault();
    }

    /// <summary>
    /// Finds the API resources that contain the scope.
    /// </summary>
    /// <param name="resources">The resources.</param>
    /// <param name="name">The name.</param>
    /// <returns></returns>
    public static IEnumerable<ApiResource> FindApiResourcesByScope(this Resources resources, string name) =>
        (from api in resources.ApiResources
         where api.Scopes.Contains(name)
         select api).ToArray();

    /// <summary>
    /// Finds the API scope.
    /// </summary>
    /// <param name="resources">The resources.</param>
    /// <param name="name">The name.</param>
    /// <returns></returns>
    public static ApiScope FindApiScope(this Resources resources, string name)
    {
        var q = from scope in resources.ApiScopes
                where scope.Name == name
                select scope;
        return q.FirstOrDefault();
    }

    internal static Resources FilterEnabled(this Resources resources)
    {
        if (resources == null) return new Resources();

        return new Resources(
                             resources.IdentityResources.Where(x => x.Enabled),
                             resources.ApiResources.Where(x => x.Enabled),
                             resources.ApiScopes.Where(x => x.Enabled))
        {
            OfflineAccess = resources.OfflineAccess
        };
    }

    internal static string[] FindMatchingSigningAlgorithms(this IEnumerable<ApiResource> apiResources) {
        var resources = Seq(apiResources);
        if (!resources.Any())
            return System.Array.Empty<string>(); // it's ok if we don't have any API resources..?

        var allAlgorithms = resources.Select(r => r.AllowedAccessTokenSigningAlgorithms)
                                     .Aggregate((x, y) => x.Intersect(y).ToArray())
                                     .ToArray();
        // resources need to agree on allowed signing algorithms
        if (!allAlgorithms.Any())
            throw new InvalidOperationException("Signing algorithms requirements for requested resources are not compatible.");

        return allAlgorithms;
    }
}