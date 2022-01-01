// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
// ReSharper disable NotAccessedPositionalProperty.Global

namespace IdentityServer4.Models;

/// <summary>
/// A model for a persisted grant
/// </summary>
/// <param name="Description">the description the user assigned to the device being authorized.</param>
public sealed record PersistedGrant(string Key, string Type, string ClientId, string SubjectId, Option<string> SessionId, string? Description,
                                    DateTime CreationTime, DateTime Expiration, Option<DateTime> ConsumedTime, string Data);