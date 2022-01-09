// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Principal;

namespace IdentityServer4.Extensions;

/// <summary>
/// Extension methods for <see cref="System.Security.Principal.IPrincipal"/> and <see cref="System.Security.Principal.IIdentity"/> .
/// </summary>
public static class PrincipalExtensions
{
    /// <summary>
    /// Gets the authentication time.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<DateTime> GetAuthenticationTime(this IPrincipal principal) =>
        principal.GetAuthenticationTimeEpoch().Map(e => DateTimeOffset.FromUnixTimeSeconds(e).UtcDateTime);

    /// <summary>
    /// Gets the authentication epoch time.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<long> GetAuthenticationTimeEpoch(this IPrincipal principal) => principal.Identity!.GetAuthenticationTimeEpoch();

    /// <summary>
    /// Gets the authentication epoch time.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<long> GetAuthenticationTimeEpoch(this IIdentity identity) => identity.GetClaim(JwtClaimTypes.AuthenticationTime, long.Parse);

    /// <summary>
    /// Gets the subject identifier.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<string> GetSubjectId(this IPrincipal principal) => principal.Identity!.GetSubjectId();

    /// <summary>
    /// Gets the subject identifier.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">sub claim is missing</exception>
    [DebuggerStepThrough]
    public static Option<string> GetSubjectId(this IIdentity identity) => identity.GetClaim(JwtClaimTypes.Subject);

    /// <summary>
    /// Gets the name.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    [Obsolete("This method will be removed in a future version. Use GetDisplayName instead.")]
    public static Option<string> GetName(this IPrincipal principal) => principal.Identity!.GetName();

    /// <summary>
    /// Gets the name.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static string GetDisplayName(this ClaimsPrincipal principal)
    {
        var name = principal.Identity!.Name;
        if (name.IsPresent()) return name!;

        var sub = principal.FindFirst(JwtClaimTypes.Subject);
        return sub != null ? sub.Value : string.Empty;
    }

    /// <summary>
    /// Gets the name.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">name claim is missing</exception>
    [DebuggerStepThrough]
    [Obsolete("This method will be removed in a future version. Use GetDisplayName instead.")]
    public static Option<string> GetName(this IIdentity identity) => identity.GetClaim(JwtClaimTypes.Name);

    /// <summary>
    /// Gets the authentication method.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<string> GetAuthenticationMethod(this IPrincipal principal) => principal.Identity!.GetAuthenticationMethod();

    /// <summary>
    /// Gets the authentication method claims.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static IEnumerable<Claim> GetAuthenticationMethods(this IPrincipal principal) => principal.Identity!.GetAuthenticationMethods();

    /// <summary>
    /// Gets the authentication method.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">amr claim is missing</exception>
    [DebuggerStepThrough]
    public static Option<string> GetAuthenticationMethod(this IIdentity identity) => identity.GetClaim(JwtClaimTypes.AuthenticationMethod);

    /// <summary>
    /// Gets the authentication method claims.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static IEnumerable<Claim> GetAuthenticationMethods(this IIdentity identity)
    {
        var id = (ClaimsIdentity)identity;
        return id.FindAll(JwtClaimTypes.AuthenticationMethod);
    }

    /// <summary>
    /// Gets the identity provider.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<string> GetIdentityProvider(this IPrincipal principal) => principal.Identity!.GetIdentityProvider();

    /// <summary>
    /// Gets the identity provider.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">idp claim is missing</exception>
    [DebuggerStepThrough]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Option<string> GetIdentityProvider(this IIdentity identity) => identity.GetClaim(JwtClaimTypes.IdentityProvider);

    /// <summary>
    /// Determines whether this instance is authenticated.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns>
    ///   <c>true</c> if the specified principal is authenticated; otherwise, <c>false</c>.
    /// </returns>
    [DebuggerStepThrough]
    public static bool IsAuthenticated(this IPrincipal principal) => principal.Identity!.IsAuthenticated;

    /// <summary>
    /// Get claim through a principal.
    /// </summary>
    /// <param name="principal"></param>
    /// <param name="claimType"></param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<string> GetClaim(this IPrincipal principal, string claimType) => principal.Identity?.GetClaim(claimType, x => x) ?? None;
    /// <summary>
    /// Get claim through a principal.
    /// </summary>
    [DebuggerStepThrough]
    public static Option<T> GetClaim<T>(this IPrincipal principal, string claimType, Func<string,T> converter) => principal.Identity?.GetClaim(claimType, converter) ?? None;
    /// <summary>
    /// Get claim through an identity.
    /// </summary>
    /// <param name="identity"></param>
    /// <param name="claimType"></param>
    /// <returns></returns>
    [DebuggerStepThrough]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Option<string> GetClaim(this IIdentity identity, string claimType) => identity.GetClaim(claimType, x => x);
    /// <summary>
    /// Get claim through an identity with a converter.
    /// </summary>
    /// <param name="identity"></param>
    /// <param name="claimType"></param>
    /// <param name="converter"></param>
    /// <typeparam name="T"></typeparam>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static Option<T> GetClaim<T>(this IIdentity identity, string claimType, Func<string,T> converter)
    {
        var id = (ClaimsIdentity)identity;
        var claim = Optional(id.FindFirst(claimType)!);
        return claim.Map(c => converter(c.Value));
    }
}