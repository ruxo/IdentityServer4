﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores.Serialization;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Stores.Default;

/// <summary>
/// Default refresh token store.
/// </summary>
public class DefaultRefreshTokenStore : DefaultGrantStore<RefreshToken>, IRefreshTokenStore
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRefreshTokenStore"/> class.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="serializer">The serializer.</param>
    /// <param name="handleGenerationService">The handle generation service.</param>
    /// <param name="logger">The logger.</param>
    public DefaultRefreshTokenStore(
        IPersistedGrantStore store,
        IPersistentGrantSerializer serializer,
        IHandleGenerationService handleGenerationService,
        ILogger<DefaultRefreshTokenStore> logger)
        : base(IdentityServerConstants.PersistedGrantTypes.RefreshToken, store, serializer, handleGenerationService, logger)
    {
    }

    /// <summary>
    /// Stores the refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <returns></returns>
    public Task<string> StoreRefreshTokenAsync(RefreshToken refreshToken) =>
        CreateItemAsync(refreshToken,
                        refreshToken.ClientId,
                        refreshToken.SubjectId,
                        refreshToken.SessionId,
                        refreshToken.Description,
                        refreshToken.CreationTime,
                        refreshToken.Lifetime);

    /// <summary>
    /// Updates the refresh token.
    /// </summary>
    /// <param name="handle">The handle.</param>
    /// <param name="refreshToken">The refresh token.</param>
    /// <returns></returns>
    public Task UpdateRefreshTokenAsync(string handle, RefreshToken refreshToken) =>
        StoreItemAsync(handle,
                       refreshToken,
                       refreshToken.ClientId,
                       refreshToken.SubjectId,
                       refreshToken.SessionId,
                       refreshToken.Description,
                       refreshToken.CreationTime,
                       refreshToken.CreationTime.AddSeconds(refreshToken.Lifetime),
                       refreshToken.ConsumedTime);

    /// <summary>
    /// Gets the refresh token.
    /// </summary>
    /// <param name="refreshTokenHandle">The refresh token handle.</param>
    /// <returns></returns>
    public Task<Option<RefreshToken>> GetRefreshTokenAsync(string refreshTokenHandle) => GetItemAsync(refreshTokenHandle);

    /// <summary>
    /// Removes the refresh token.
    /// </summary>
    /// <param name="refreshTokenHandle">The refresh token handle.</param>
    /// <returns></returns>
    public Task RemoveRefreshTokenAsync(string refreshTokenHandle) => RemoveItemAsync(refreshTokenHandle);

    /// <summary>
    /// Removes the refresh tokens.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <returns></returns>
    public Task RemoveRefreshTokensAsync(string subjectId, string clientId) => RemoveAllAsync(subjectId, clientId);
}