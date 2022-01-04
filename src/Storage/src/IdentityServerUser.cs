// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Extensions;
using System;
using System.Linq;
using System.Security.Claims;

namespace IdentityServer4;

/// <summary>
/// Model properties of an IdentityServer user
/// </summary>
class IdentityServerUser
{
    /// <summary>
    /// Subject ID (mandatory)
    /// </summary>
    public string SubjectId { get; } = string.Empty;

    /// <summary>
    /// Display name (optional)
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Identity provider (optional)
    /// </summary>
    public string? IdentityProvider { get; set; }

    /// <summary>
    /// Authentication methods
    /// </summary>
    public string[] AuthenticationMethods { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Authentication time
    /// </summary>
    public DateTime? AuthenticationTime { get; set; }

    /// <summary>
    /// Additional claims
    /// </summary>
    public HashSet<Claim> AdditionalClaims { get; } = new(new ClaimComparer());

    /// <summary>
    /// Initializes a user identity
    /// </summary>
    /// <param name="subjectId">The subject ID</param>
    public IdentityServerUser(string subjectId)
    {
        if (subjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(subjectId));

        SubjectId = subjectId;
    }

    /// <summary>
    /// Creates an IdentityServer claims principal
    /// </summary>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public ClaimsPrincipal CreatePrincipal()
    {
        if (SubjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(SubjectId));
        var claims = new List<Claim> { new(JwtClaimTypes.Subject, SubjectId) };

        if (DisplayName.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.Name, DisplayName));
        }

        if (IdentityProvider.IsPresent())
        {
            claims.Add(new(JwtClaimTypes.IdentityProvider, IdentityProvider));
        }

        if (AuthenticationTime.HasValue)
        {
            claims.Add(new(JwtClaimTypes.AuthenticationTime, new DateTimeOffset(AuthenticationTime.Value).ToUnixTimeSeconds().ToString()));
        }

        if (AuthenticationMethods.Any())
        {
            foreach (var amr in AuthenticationMethods)
            {
                claims.Add(new(JwtClaimTypes.AuthenticationMethod, amr));
            }
        }

        claims.AddRange(AdditionalClaims);

        var id = new ClaimsIdentity(claims.Distinct(new ClaimComparer()), Constants.IdentityServerAuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
        return new(id);
    }
}