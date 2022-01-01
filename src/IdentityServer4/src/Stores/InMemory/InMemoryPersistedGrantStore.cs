// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Concurrent;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;

namespace IdentityServer4.Stores.InMemory;

/// <summary>
/// In-memory persisted grant store
/// </summary>
public class InMemoryPersistedGrantStore : IPersistedGrantStore
{
    readonly ConcurrentDictionary<string, PersistedGrant> repository = new();

    /// <inheritdoc/>
    public Task StoreAsync(PersistedGrant grant)
    {
        repository[grant.Key] = grant;

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<Option<PersistedGrant>> GetAsync(string key) =>
        Task.FromResult(repository.TryGetValue(key, out var token) ? Some(token) : None);

    /// <inheritdoc/>
    public Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter)
    {
        filter.Validate();

        var items = Filter(filter);

        return Task.FromResult(items);
    }

    /// <inheritdoc/>
    public Task RemoveAsync(string key)
    {
        repository.TryRemove(key, out _);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task RemoveAllAsync(PersistedGrantFilter filter)
    {
        filter.Validate();

        var items = Filter(filter);

        foreach (var item in items)
        {
            repository.TryRemove(item.Key, out _);
        }

        return Task.CompletedTask;
    }

    IEnumerable<PersistedGrant> Filter(PersistedGrantFilter filter)
    {
        var query =
            from item in repository
            select item.Value;

        if (!String.IsNullOrWhiteSpace(filter.ClientId))
        {
            query = query.Where(x => x.ClientId == filter.ClientId);
        }
        if (!String.IsNullOrWhiteSpace(filter.SessionId))
        {
            query = query.Where(x => x.SessionId == filter.SessionId);
        }
        if (!String.IsNullOrWhiteSpace(filter.SubjectId))
        {
            query = query.Where(x => x.SubjectId == filter.SubjectId);
        }
        if (!String.IsNullOrWhiteSpace(filter.Type))
        {
            query = query.Where(x => x.Type == filter.Type);
        }

        var items = query.ToArray().AsEnumerable();
        return items;
    }
}