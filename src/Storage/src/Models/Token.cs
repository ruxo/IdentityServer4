// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System;
using System.Linq;
using System.Security.Claims;

namespace IdentityServer4.Models;

/// <summary>
/// Models a token.
/// </summary>
/// <param name="Description">the description the user assigned to the device being authorized.</param>
/// <param name="Confirmation">Specifies the confirmation method of the token. This value, if set, will become the cnf claim.</param>
/// <param name="AllowedSigningAlgorithms">A list of allowed algorithm for signing the token. If null or empty, will use the default algorithm.</param>
public sealed record Token(string Type, string ClientId, string? Description, Claim[] Claims, Option<string> Confirmation,
                           Option<string[]> AllowedSigningAlgorithms, string[] Audiences, string Issuer, DateTime CreationTime, int Lifetime,
                           AccessTokenType AccessTokenType)
{
    //public Token() : this(OidcConstants.TokenTypes.AccessToken){}
    /// <summary>
    /// the version.
    /// </summary>
    public int Version => 1000; // Ruxo Zheng's version

    /// <summary>
    /// Gets the subject identifier.
    /// </summary>
    public string SubjectId => Claims.Where(x => x.Type == JwtClaimTypes.Subject).Select(x => x.Value).Single();

    /// <summary>
    /// Gets the session identifier.
    /// </summary>
    public Option<string> SessionId => Claims.Where(x => x.Type == JwtClaimTypes.SessionId).Select(x => x.Value).TrySingle();

    /// <summary>
    /// Gets the scopes.
    /// </summary>
    public IEnumerable<string> Scopes => Claims.Where(x => x.Type == JwtClaimTypes.Scope).Select(x => x.Value);
}