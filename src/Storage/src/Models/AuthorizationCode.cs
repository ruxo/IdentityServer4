// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IdentityServer4.Models;

/// <summary>
/// PKCE data
/// </summary>
/// <param name="CodeChallenge"></param>
/// <param name="CodeChallengeMethod"></param>
public sealed record PkceData(string CodeChallenge, string CodeChallengeMethod);

/// <summary>
/// Models an authorization code.
/// </summary>
/// <param name="Lifetime">the life time in seconds.</param>
/// <param name="Description">the description the user assigned to the device being authorized.</param>
/// <param name="IsOpenId">a value indicating whether this code is an OpenID Connect code.</param>
/// <param name="StateHash">the hashed state (to output s_hash claim).</param>
public sealed record AuthorizationCode(DateTime CreationTime, string ClientId, int Lifetime, string SubjectId, string SessionId, Option<string> Description,
                                       Option<PkceData> Pkce, bool IsOpenId, string[] RequestedScopes, string RedirectUri,
                                       Option<string> Nonce, Option<string> StateHash, bool WasConsentShown) : IAuthorizationModel
{
    /// <inheritdoc />
    public string[] Scopes => RequestedScopes;
}
// TODO clean up
/*
{
    /// <summary>
    /// Gets or sets properties
    /// </summary>
    /// <value>
    /// The properties
    /// </value>
    public Dictionary<string, string> Properties { get; set; } = new();
}
*/