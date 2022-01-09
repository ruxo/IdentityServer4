using System;
using System.Security.Claims;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Authentication;

namespace IdentityServer4.Models;

/// <summary>
/// Represent current user authentication state
/// </summary>
/// <param name="Subject">User claims</param>
/// <param name="Properties">States</param>
public readonly record struct UserSession(ClaimsPrincipal Subject, AuthenticationProperties Properties)
{
    /// <summary>
    /// Is this principal from an authenticated identity?
    /// </summary>
    public bool IsAuthenticated => Subject.Identity!.IsAuthenticated;

    /// <summary>
    /// Get an authenticated user
    /// </summary>
    /// <exception cref="InvalidOperationException"></exception>
    public AuthenticatedUser AuthenticatedUser => AuthenticatedUser.FromPrincipal(Subject);

    /// <summary>
    /// Get session ID
    /// </summary>
    public Option<string> SessionId => Properties.GetSessionId();
}

/// <summary>
/// Represent an authenticated user
/// </summary>
/// <param name="Subject"></param>
public readonly record struct AuthenticatedUser(ClaimsPrincipal Subject)
{
    /// <summary>
    /// Create authenticated user from a subject
    /// </summary>
    /// <param name="subject"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static AuthenticatedUser FromPrincipal(ClaimsPrincipal subject) =>
        subject.Identity!.IsAuthenticated? new(subject) : throw new InvalidOperationException($"User {subject.Identity?.Name} is not authenticated");

    /// <summary>
    /// Gets the authentication time.
    /// </summary>
    public DateTime AuthenticationTime => Subject.GetAuthenticationTime().Get();
    /// <summary>
    /// Gets the authentication epoch time.
    /// </summary>
    public long AuthenticationTimeEpoch => Subject.GetAuthenticationTimeEpoch().Get();
    /// <summary>
    /// Get Identity Provider
    /// </summary>
    public string IdentityProvider => Subject.GetIdentityProvider().Get();
    /// <summary>
    /// Subject identifier
    /// </summary>
    public string SubjectId => Subject.GetSubjectId().Get();

    /// <summary>
    /// Gets the authentication method.
    /// </summary>
    public IEnumerable<Claim> AuthenticationMethods => Subject.GetAuthenticationMethods();
}