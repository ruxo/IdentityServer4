// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Stores;

/// <summary>
/// Extension for IClientStore
/// </summary>
public static class IClientStoreExtensions
{
    /// <summary>
    /// Finds the enabled client by identifier.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <returns></returns>
    public static Task<Option<Client>> FindEnabledClientByIdAsync(this IClientStore store, string clientId) =>
        store.FindClientByIdAsync(clientId).Where(c => c.Enabled);
}