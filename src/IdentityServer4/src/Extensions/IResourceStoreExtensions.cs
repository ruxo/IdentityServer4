// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Extensions;

/// <summary>
/// Extensions for IResourceStore
/// </summary>
public static class IResourceStoreExtensions
{
    /// <summary>
    /// Finds the resources by scope.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="scopeNames">The scope names.</param>
    /// <returns></returns>
    public static async Task<IEnumerable<Resource>> FindResourcesByScopeAsync(this IResourceStore store, IEnumerable<string> scopeNames)
    {
        var names = scopeNames.AsArray();
        var identity = (await store.FindIdentityResourcesByScopeNameAsync(names)).AsArray();
        var apiResources = (await store.FindApiResourcesByScopeNameAsync(names)).AsArray();
        var scopes = (await store.FindApiScopesByNameAsync(names)).AsArray();

        return identity.Cast<Resource>().Concat(apiResources).Concat(scopes);
    }

    /// <summary>
    /// Finds the enabled resources by scope.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="scopeNames">The scope names.</param>
    /// <returns></returns>
    public static async Task<IEnumerable<Resource>> FindEnabledResourcesByScopeAsync(this IResourceStore store, IEnumerable<string> scopeNames) =>
        (await store.FindResourcesByScopeAsync(scopeNames)).Where(r => r.Enabled);

    /// <summary>
    /// Creates a resource validation result.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="validScopeValues">The parsed scopes.</param>
    /// <returns></returns>
    public static Task<IEnumerable<Resource>> FindAllResources(this IResourceStore store, ParsedScopeValue[] validScopeValues) =>
        store.FindEnabledResourcesByScopeAsync(validScopeValues.Select(x => x.Name));

    /// <summary>
    /// Gets all enabled resources.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <returns></returns>
    public static async Task<IEnumerable<Resource>> GetAllEnabledResourcesAsync(this IResourceStore store) =>
        (await store.GetAllResourcesAsync()).Where(r => r.Enabled);

    /// <summary>
    /// Finds the enabled identity resources by scope.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="scopeNames">The scope names.</param>
    /// <returns></returns>
    public static async Task<IEnumerable<IdentityResource>> FindEnabledIdentityResourcesByScopeAsync(this IResourceStore store, IEnumerable<string> scopeNames) =>
        (await store.FindIdentityResourcesByScopeNameAsync(scopeNames)).Where(x => x.Enabled);
}