// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;
using IdentityServer4.Validation.Models;

namespace IdentityServer4.Models.Contexts;

/// <summary>
/// Class describing the profile data request
/// </summary>
public sealed record ProfileDataRequestContext(ClaimsPrincipal Subject, Client Client, string Caller, string[] RequestedClaimTypes, Option<ResourceValidationResult> RequestedResources);