// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Models;

namespace IdentityServer4.Stores.InMemory;

/// <summary>
/// The default validation key store
/// </summary>
/// <seealso cref="IdentityServer4.Stores.IValidationKeysStore" />
public class InMemoryValidationKeysStore : IValidationKeysStore
{
    readonly IEnumerable<SecurityKeyInfo> keys;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryValidationKeysStore"/> class.
    /// </summary>
    /// <param name="keys">The keys.</param>
    /// <exception cref="System.ArgumentNullException">keys</exception>
    public InMemoryValidationKeysStore(IEnumerable<SecurityKeyInfo> keys)
    {
        this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
    }

    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    public IAsyncEnumerable<SecurityKeyInfo> GetValidationKeysAsync() => keys.AsAsyncEnumerable();
}