// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Configuration;
using LanguageExt;
using Microsoft.Extensions.Logging;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Stores
{
    /// <summary>
    /// Cache decorator for IClientStore
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <seealso cref="IdentityServer4.Stores.IClientStore" />
    public class CachingClientStore<T> : IClientStore
        where T : IClientStore
    {
        private readonly IdentityServerOptions _options;
        private readonly ICache<Client> _cache;
        private readonly IClientStore _inner;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachingClientStore{T}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="inner">The inner.</param>
        /// <param name="cache">The cache.</param>
        /// <param name="logger">The logger.</param>
        public CachingClientStore(IdentityServerOptions options, T inner, ICache<Client> cache, ILogger<CachingClientStore<T>> logger)
        {
            _options = options;
            _inner = inner;
            _cache = cache;
            _logger = logger;
        }

        /// <summary>
        /// Finds a client by id
        /// </summary>
        /// <param name="clientId">The client id</param>
        /// <returns>
        /// The client
        /// </returns>
        public OptionAsync<Client> FindClientByIdAsync(string clientId) =>
            _cache.GetAsync(clientId,
                _options.Caching.ClientStoreExpiration,
                async () => await _inner.FindClientByIdAsync(clientId),
                _logger);
    }
}