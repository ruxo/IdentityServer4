// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Models;

/// <summary>
/// Represents a secret extracted from the HttpContext
/// </summary>
/// <param name="Type">the credential to verify the secret</param>
/// <param name="Id">the identifier associated with this secret</param>
public sealed record ParsedSecret(string Type, string Id, Option<string> Credential);