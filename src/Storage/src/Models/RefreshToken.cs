// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Security.Claims;

namespace IdentityServer4.Models;

/// <summary>
/// Models a refresh token.
/// </summary>
public sealed record RefreshToken(Token AccessToken, int Lifetime, Option<DateTime> ConsumedTime, DateTime CreationTime)
{
    /// <summary>
    /// Gets or sets the original subject that requested the token.
    /// </summary>
    /// <value>
    /// The subject.
    /// </value>
    public ClaimsPrincipal Subject
    {
        get
        {
            var user = new IdentityServerUser(SubjectId);
            foreach (var claim in AccessToken.Claims) {
                user.AdditionalClaims.Add(claim);
            }
            return user.CreatePrincipal();
        }
    }

    /// <summary>
    /// the version number.
    /// </summary>
    public int Version => 1000;

    /// <summary>
    /// Gets the client identifier.
    /// </summary>
    /// <value>
    /// The client identifier.
    /// </value>
    public string ClientId => AccessToken.ClientId;

    /// <summary>
    /// Gets the subject identifier.
    /// </summary>
    /// <value>
    /// The subject identifier.
    /// </value>
    public string SubjectId => AccessToken.SubjectId;

    /// <summary>
    /// Gets the session identifier.
    /// </summary>
    /// <value>
    /// The session identifier.
    /// </value>
    public Option<string> SessionId => AccessToken.SessionId;

    /// <summary>
    /// Gets the description the user assigned to the device being authorized.
    /// </summary>
    /// <value>
    /// The description.
    /// </value>
    public string? Description => AccessToken.Description;

    /// <summary>
    /// Gets the scopes.
    /// </summary>
    /// <value>
    /// The scopes.
    /// </value>
    public IEnumerable<string> Scopes => AccessToken.Scopes;
}