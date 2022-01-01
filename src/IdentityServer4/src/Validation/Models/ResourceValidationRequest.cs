// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Models the request to validate scopes and resource indicators for a client.
/// </summary>
public sealed record ResourceValidationRequest(Client Client, string[] Scopes);