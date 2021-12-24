// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Threading.Tasks;
using IdentityServer4.Configuration;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using RZ.Foundation.Extensions;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Stores
{
    /// <summary>
    /// Caching decorator for IResourceStore
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <seealso cref="IdentityServer4.Stores.IResourceStore" />
    public class CachingResourceStore<T> : IResourceStore
        where T : IResourceStore
    {
        const string AllKey = "__all__";

        readonly IdentityServerOptions options;

        readonly ICache<IEnumerable<IdentityResource>> identityCache;
        readonly ICache<IEnumerable<ApiResource>> apiByScopeCache;
        readonly ICache<IEnumerable<ApiScope>> apiScopeCache;
        readonly ICache<IEnumerable<ApiResource>> apiResourceCache;
        readonly ICache<Resources> allCache;

        readonly IResourceStore inner;
        readonly ILogger logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachingResourceStore{T}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="inner">The inner.</param>
        /// <param name="identityCache">The identity cache.</param>
        /// <param name="apiByScopeCache">The API by scope cache.</param>
        /// <param name="apisCache">The API cache.</param>
        /// <param name="scopeCache"></param>
        /// <param name="allCache">All cache.</param>
        /// <param name="logger">The logger.</param>
        public CachingResourceStore(IdentityServerOptions options, T inner,
            ICache<IEnumerable<IdentityResource>> identityCache,
            ICache<IEnumerable<ApiResource>> apiByScopeCache,
            ICache<IEnumerable<ApiResource>> apisCache,
            ICache<IEnumerable<ApiScope>> scopeCache,
            ICache<Resources> allCache,
            ILogger<CachingResourceStore<T>> logger)
        {
            this.options = options;
            this.inner = inner;
            this.identityCache = identityCache;
            this.apiByScopeCache = apiByScopeCache;
            apiResourceCache = apisCache;
            apiScopeCache = scopeCache;
            this.allCache = allCache;
            this.logger = logger;
        }

        static string GetKey(IEnumerable<string> names) => names.OrderBy(x => x).Join(',');

        /// <inheritdoc/>
        public Task<Resources> GetAllResourcesAsync() =>
            allCache.GetAsync(AllKey, options.Caching.ResourceStoreExpiration, inner.GetAllResourcesAsync, logger)
                     .IfNone(() => throw new InvalidOperationException());

        /// <inheritdoc/>
        public Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames) =>
            FindItemsFromCache(apiResourceCache, inner.FindApiResourcesByNameAsync, apiResourceNames);

        /// <inheritdoc/>
        public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> names) =>
            FindItemsFromCache(identityCache, inner.FindIdentityResourcesByScopeNameAsync, names);

        /// <inheritdoc/>
        public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> names) =>
            FindItemsFromCache(apiByScopeCache, inner.FindApiResourcesByScopeNameAsync, names);

        /// <inheritdoc/>
        public Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames) =>
            FindItemsFromCache(apiScopeCache, inner.FindApiScopesByNameAsync, scopeNames);

        Task<IEnumerable<TA>> FindItemsFromCache<TA>(ICache<IEnumerable<TA>> cache, Func<IEnumerable<string>, Task<IEnumerable<TA>>> loader,
                                                       IEnumerable<string>    keys)
            where TA : class {
            var n = Seq(keys);
            var key = GetKey(n);

            return cache.GetAsync(key, options.Caching.ResourceStoreExpiration, () => loader(n), logger)
                        .IfNone(Enumerable.Empty<TA>());
        }
    }
}