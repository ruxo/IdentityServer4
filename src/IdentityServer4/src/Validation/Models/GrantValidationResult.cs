// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Models;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Grant validation error.
/// </summary>
public sealed record GrantValidationError(string Error, string? ErrorDescription, Dictionary<string, object> CustomResponse)
    : ErrorInfo(Error, ErrorDescription)
{
    /// <summary>
    /// Init
    /// </summary>
    public static GrantValidationError Create(TokenRequestErrors error, string? description = null, Dictionary<string, object>? customResponse = null) =>
        new(ConvertTokenErrorEnumToString(error), description, customResponse ?? new Dictionary<string, object>());

    static string ConvertTokenErrorEnumToString(TokenRequestErrors error) =>
        error switch
        {
            TokenRequestErrors.InvalidClient        => OidcConstants.TokenErrors.InvalidClient,
            TokenRequestErrors.InvalidGrant         => OidcConstants.TokenErrors.InvalidGrant,
            TokenRequestErrors.InvalidRequest       => OidcConstants.TokenErrors.InvalidRequest,
            TokenRequestErrors.InvalidScope         => OidcConstants.TokenErrors.InvalidScope,
            TokenRequestErrors.UnauthorizedClient   => OidcConstants.TokenErrors.UnauthorizedClient,
            TokenRequestErrors.UnsupportedGrantType => OidcConstants.TokenErrors.UnsupportedGrantType,
            TokenRequestErrors.InvalidTarget        => OidcConstants.TokenErrors.InvalidTarget,
            _                                       => throw new InvalidOperationException("invalid token error")
        };
}

/// <summary>
/// Models the result of custom grant validation.
/// </summary>
public sealed record GrantValidationResult(ClaimsPrincipal Subject, Dictionary<string, object> CustomResponse)
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GrantValidationResult"/> class with a given principal.
    /// Warning: the principal needs to include the required claims - it is recommended to use the other constructor that does validation.
    /// </summary>
    public static GrantValidationResult Create(ClaimsPrincipal principal, Dictionary<string, object>? customResponse = null)
    {
        if (principal.Identities.Count() != 1) throw new InvalidOperationException("only a single identity supported");
        if (principal.FindFirst(JwtClaimTypes.Subject) == null) throw new InvalidOperationException("sub claim is missing");
        if (principal.FindFirst(JwtClaimTypes.IdentityProvider) == null) throw new InvalidOperationException("idp claim is missing");
        if (principal.FindFirst(JwtClaimTypes.AuthenticationMethod) == null) throw new InvalidOperationException("amr claim is missing");
        if (principal.FindFirst(JwtClaimTypes.AuthenticationTime) == null) throw new InvalidOperationException("auth_time claim is missing");
        return new(principal, customResponse ?? new Dictionary<string, object>());
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GrantValidationResult" /> class.
    /// </summary>
    /// <param name="subject">The subject claim used to uniquely identifier the user.</param>
    /// <param name="authenticationMethod">The authentication method which describes the custom grant type.</param>
    /// <param name="authTime">The UTC date/time of authentication.</param>
    /// <param name="claims">Additional claims that will be maintained in the principal.
    /// If you want these claims to appear in token, you need to add them explicitly in your custom implementation of <see cref="Services.IProfileService"/> service.</param>
    /// <param name="identityProvider">The identity provider.</param>
    /// <param name="customResponse">The custom response.</param>
    public static GrantValidationResult Create(
        string subject,
        string authenticationMethod,
        DateTime? authTime,
        IEnumerable<Claim>? claims = null,
        string identityProvider = IdentityServerConstants.LocalIdentityProvider,
        Dictionary<string, object>? customResponse = null)
    {
        var resultClaims = new Claim[]
        {
            new(JwtClaimTypes.Subject, subject),
            new(JwtClaimTypes.AuthenticationMethod, authenticationMethod),
            new(JwtClaimTypes.IdentityProvider, identityProvider),
            new(JwtClaimTypes.AuthenticationTime, new DateTimeOffset(authTime ?? DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        }.Concat(claims ?? Enumerable.Empty<Claim>());

        var id = new ClaimsIdentity(authenticationMethod);
        id.AddClaims(resultClaims.Distinct(new ClaimComparer()));

        return new(new(id), customResponse ?? new Dictionary<string, object>());
    }
}