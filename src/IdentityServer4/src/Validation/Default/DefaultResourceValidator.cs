// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default implementation of IResourceValidator.
/// </summary>
public sealed class DefaultResourceValidator : IResourceValidator
{
    readonly ILogger logger;
    readonly IResourceStore store;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultResourceValidator"/> class.
    /// </summary>
    /// <param name="store">The store.</param>
    /// <param name="logger">The logger.</param>
    public DefaultResourceValidator(IResourceStore store, ILogger<DefaultResourceValidator> logger)
    {
        this.logger      = logger;
        this.store       = store;
    }

    /// <inheritdoc/>
    public async Task<(Resource[] RequestedResources, ParsedScopeValidationError[] InvalidScopes)> ValidateScopesWithClient(Client client, IEnumerable<ParsedScopeValue> parsedScopes)
    {
        var scopeNames = parsedScopes.Select(x => x.Name).ToArray();
        var resources = (await store.FindEnabledResourcesByScopeAsync(scopeNames)).AsArray();

        var failedScopes = ValidateResourcesWithClient(client, resources).ToArray();
        var finalResources = resources.Where(r => failedScopes.All(fs => fs.Scope != r.Name)).ToArray();

        failedScopes.Iter(invalidScope => logger.LogError("Invalid parsed scope {Scope}, message: {Reason}", invalidScope.Scope, invalidScope.Reason));

        return (finalResources, failedScopes);
    }

    static IEnumerable<ParsedScopeValidationError> ValidateResourcesWithClient(Client client, IEnumerable<Resource> resources) {
        foreach (var resource in resources)
            if (resource.Name == IdentityServerConstants.StandardScopes.OfflineAccess && !client.AllowOfflineAccess)
                yield return new(resource.Name, "Offline access is not allowed!");
            else if (!client.AllowedScopes.Contains(resource.Name))
                yield return new(resource.Name, $"Client {client.ClientId} is not allowed access to scope {resource.Name}");
    }
}