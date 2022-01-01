// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityServer4.Models.Contexts;

/// <summary>
/// Provides the context necessary to construct a logout notificaiton.
/// </summary>
/// <param name="SubjectId">The subject ID of the user.</param>
/// <param name="SessionId">The session Id of the user's authentication session.</param>
/// <param name="ClientIds">The list of client Ids that the user has authenticated to.</param>
public sealed record LogoutNotificationContext(string SubjectId, Option<string> SessionId, string[] ClientIds);