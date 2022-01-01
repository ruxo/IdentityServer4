// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.Services.Default;

/// <summary>
/// The default key material service
/// </summary>
/// <seealso cref="IdentityServer4.Services.IKeyMaterialService" />
public class DefaultKeyMaterialService : IKeyMaterialService
{
    readonly IEnumerable<ISigningCredentialStore> signingCredentialStores;
    readonly IEnumerable<IValidationKeysStore> validationKeysStores;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultKeyMaterialService"/> class.
    /// </summary>
    /// <param name="validationKeysStores">The validation keys stores.</param>
    /// <param name="signingCredentialStores">The signing credential store.</param>
    public DefaultKeyMaterialService(IEnumerable<IValidationKeysStore> validationKeysStores, IEnumerable<ISigningCredentialStore> signingCredentialStores)
    {
        this.signingCredentialStores = signingCredentialStores;
        this.validationKeysStores = validationKeysStores;
    }

    /// <inheritdoc/>
    public async Task<Option<SigningCredentials>> GetSigningCredentialsAsync(IEnumerable<string> allowedAlgorithms)
    {
        if (!signingCredentialStores.Any()) return None;
        var allowed = Seq(allowedAlgorithms);
        if (!allowed.Any())
            return await signingCredentialStores.First().GetSigningCredentialsAsync();

        var credential = (await GetAllSigningCredentialsAsync()).TryFirst(c => allowed.Contains(c.Algorithm));
        if (credential.IsNone)
            throw new InvalidOperationException($"No signing credential for algorithms ({allowed.ToSpaceSeparatedString()}) registered.");

        return credential;
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<SigningCredentials>> GetAllSigningCredentialsAsync()
    {
        var credentials = new List<SigningCredentials>();

        foreach (var store in signingCredentialStores)
        {
            credentials.Add(await store.GetSigningCredentialsAsync());
        }

        return credentials;
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<SecurityKeyInfo> GetValidationKeysAsync() => validationKeysStores.FlattenT(store => store.GetValidationKeysAsync());
}