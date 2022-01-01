// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LanguageExt;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Stores
{
    /// <summary>
    /// In-memory client store
    /// </summary>
    public class InMemoryClientStore : IClientStore
    {
        readonly IEnumerable<Client> _clients;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryClientStore"/> class.
        /// </summary>
        /// <param name="clients">The clients.</param>
        public InMemoryClientStore(IEnumerable<Client> clients)
        {
            var seq = Seq(clients);
            if (seq.HasDuplicates(m => m.ClientId))
                throw new ArgumentException("Clients must not contain duplicate ids");
            _clients = seq;
        }

        /// <summary>
        /// Finds a client by id
        /// </summary>
        /// <param name="clientId">The client id</param>
        /// <returns>
        /// The client
        /// </returns>
        public Task<Option<Client>> FindClientByIdAsync(string clientId) =>
            Task.FromResult(Optional((from client in _clients
                                      where client.ClientId == clientId
                                      select client).SingleOrDefault()!));
    }
}