// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.Stores
{
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
        public Task<Resources> GetAllResourcesAsync() => Task.FromResult(new Resources(identityResources, apiResources, apiScopes));

        /// <inheritdoc/>
        public Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames) =>
            Task.FromResult(from a in apiResources
                            where apiResourceNames.Contains(a.Name)
                            select a);

        /// <inheritdoc/>
        public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> scopeNames) =>
            Task.FromResult(from i in identityResources
                            where scopeNames.Contains(i.Name)
                            select i);

        /// <inheritdoc/>
        public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames) =>
            Task.FromResult(from a in apiResources
                            where a.Scopes.Any(scopeNames.Contains)
                            select a);

        /// <inheritdoc/>
        public Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames) =>
            Task.FromResult(from x in apiScopes
                            where scopeNames.Contains(x.Name)
                            select x);
    }
}