// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;

namespace IdentityServer4.Stores.InMemory;

/// <summary>
/// In-memory resource store
/// </summary>
public class InMemoryResourcesStore : IResourceStore
{
    readonly IEnumerable<IdentityResource> identityResources;
    readonly IEnumerable<ApiResource> apiResources;
    readonly IEnumerable<ApiScope> apiScopes;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryResourcesStore" /> class.
    /// </summary>
    public InMemoryResourcesStore(
        IEnumerable<IdentityResource>? identityResources = null,
        IEnumerable<ApiResource>? apiResources = null,
        IEnumerable<ApiScope>? apiScopes = null)
    {
        this.identityResources = identityResources ?? Enumerable.Empty<IdentityResource>();
        this.apiResources = apiResources ?? Enumerable.Empty<ApiResource>();
        this.apiScopes = apiScopes ?? Enumerable.Empty<ApiScope>();

        if (this.identityResources.HasDuplicates(m => m.Name))
            throw new ArgumentException("Identity resources must not contain duplicate names");

        if (this.apiResources.HasDuplicates(m => m.Name))
            throw new ArgumentException("Api resources must not contain duplicate names");

        if (this.apiScopes.HasDuplicates(m => m.Name))
            throw new ArgumentException("Scopes must not contain duplicate names");
    }

    /// <inheritdoc/>
    public Task<IEnumerable<Resource>> GetAllResourcesAsync() => Task.FromResult(identityResources.Cast<Resource>().Concat(apiResources).Concat(apiScopes));

    /// <inheritdoc/>
    public Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames) {
        var names = apiResourceNames.AsArray();
        return Task.FromResult(from a in apiResources
                               where names.Contains(a.Name)
                               select a);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> scopeNames) {
        var names = scopeNames.AsArray();
        return Task.FromResult(from i in identityResources
                               where names.Contains(i.Name)
                               select i);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames) {
        var names = scopeNames.AsArray();
        return Task.FromResult(from a in apiResources
                               where a.Scopes.Any(names.Contains)
                               select a);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames) {
        var names = scopeNames.AsArray();
        return Task.FromResult(from x in apiScopes
                               where names.Contains(x.Name)
                               select x);
    }
}