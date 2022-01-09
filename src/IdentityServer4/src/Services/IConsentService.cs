// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Services;

/// <summary>
/// Service to retrieve and update consent.
/// </summary>
public interface IConsentService
{
    /// <summary>
    /// Checks if consent is required.
    /// </summary>
    /// <param name="subjectId"></param>
    /// <param name="client">The client.</param>
    /// <param name="parsedScopes">The parsed scopes.</param>
    /// <returns>
    /// Boolean if consent is required.
    /// </returns>
    Task<bool> RequiresConsentAsync(string subjectId, Client client, IEnumerable<ParsedScopeValue> parsedScopes);

    /// <summary>
    /// Updates the consent.
    /// </summary>
    /// <param name="subjectId"></param>
    /// <param name="client">The client.</param>
    /// <param name="parsedScopes">The parsed scopes.</param>
    /// <returns></returns>
    Task UpdateConsentAsync(string subjectId, Client client, IEnumerable<ParsedScopeValue> parsedScopes);
}