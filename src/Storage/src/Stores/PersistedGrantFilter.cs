// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityServer4.Stores;

/// <summary>
/// Represents a filter used when accessing the persisted grants store.
/// Setting multiple properties is interpreted as a logical 'AND' to further filter the query.
/// At least one value must be supplied.
/// </summary>
/// <param name="Type">The type of grant.</param>
/// <param name="SubjectId">Subject id of the user.</param>
/// <param name="ClientId">Client id the grant was issued to.</param>
/// <param name="SessionId">Session id used for the grant.</param>
public sealed record PersistedGrantFilter(string SubjectId, string? Type = null, string? ClientId = null, string? SessionId = null);