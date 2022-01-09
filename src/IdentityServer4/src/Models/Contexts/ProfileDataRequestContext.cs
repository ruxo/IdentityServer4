// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.Models.Contexts;

/// <summary>
/// Class describing the profile data request
/// </summary>
public sealed record ProfileDataRequestContext(UserSession Session, Client Client, string Caller, string[] RequestedClaimTypes);