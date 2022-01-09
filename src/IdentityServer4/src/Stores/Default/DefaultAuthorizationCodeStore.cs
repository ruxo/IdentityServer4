// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores.Serialization;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Stores.Default;

/// <summary>
/// Default authorization code store.
/// </summary>
public class DefaultAuthorizationCodeStore : DefaultGrantStore<AuthorizationCode>, IAuthorizationCodeStore
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultAuthorizationCodeStore"/> class.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="serializer">The serializer.</param>
    /// <param name="handleGenerationService">The handle generation service.</param>
    /// <param name="logger">The logger.</param>
    public DefaultAuthorizationCodeStore(
        IPersistedGrantStore store,
        IPersistentGrantSerializer serializer,
        IHandleGenerationService handleGenerationService,
        ILogger<DefaultAuthorizationCodeStore> logger)
        : base(IdentityServerConstants.PersistedGrantTypes.AuthorizationCode, store, serializer, handleGenerationService, logger)
    {
    }

    /// <summary>
    /// Stores the authorization code asynchronous.
    /// </summary>
    /// <param name="code">The code.</param>
    /// <returns></returns>
    public Task<string> StoreAuthorizationCodeAsync(AuthorizationCode code) =>
        CreateItemAsync(code, code.ClientId, code.SubjectId, code.SessionId, code.Description, code.CreationTime, code.Lifetime);

    /// <summary>
    /// Gets the authorization code asynchronous.
    /// </summary>
    /// <param name="code">The code.</param>
    /// <returns></returns>
    public Task<Option<AuthorizationCode>> GetAuthorizationCodeAsync(string code) => GetItemAsync(code);

    /// <summary>
    /// Removes the authorization code asynchronous.
    /// </summary>
    /// <param name="code">The code.</param>
    /// <returns></returns>
    public Task RemoveAuthorizationCodeAsync(string code) => RemoveItemAsync(code);
}