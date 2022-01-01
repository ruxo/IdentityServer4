// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Validation
{
    /// <summary>
    /// Validates requested resources (scopes and resource indicators)
    /// </summary>
    public interface IResourceValidator
    {
        /// <summary>
        /// Validates the requested resources for the client.
        /// </summary>
        Task<(Resource[] RequestedResources, ParsedScopeValidationError[] InvalidScopes)> ValidateScopesWithClient(Client client, IEnumerable<ParsedScopeValue> parsedScopes);
    }
}