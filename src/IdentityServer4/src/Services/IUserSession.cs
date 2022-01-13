using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using IdentityServer4.Models;

namespace IdentityServer4.Services;

/// <summary>
/// Models a user's authentication session
/// </summary>
public interface IUserSession
{
    /// <summary>
    /// Creates a session identifier for the signin context and issues the session id cookie.
    /// </summary>
    Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties);

    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    ValueTask<ClaimsPrincipal> GetUserAsync();

    /// <summary>
    /// Get current user session
    /// </summary>
    /// <returns></returns>
    ValueTask<UserSession> GetCurrentSession();

    /// <summary>
    /// Gets the current session identifier.
    /// </summary>
    /// <returns></returns>
    ValueTask<Option<string>> GetSessionIdAsync();

    /// <summary>
    /// Ensures the session identifier cookie asynchronous.
    /// </summary>
    /// <returns></returns>
    Task EnsureSessionIdCookieAsync();

    /// <summary>
    /// Removes the session identifier cookie.
    /// </summary>
    Task RemoveSessionIdCookieAsync();

    /// <summary>
    /// Adds a client to the list of clients the user has signed into during their session.
    /// </summary>
    /// <returns></returns>
    Task AddClientIdAsync(UserSession session, string clientId);

    /// <summary>
    /// Gets the list of clients the user has signed into during their session.
    /// </summary>
    /// <param name="session"></param>
    /// <returns></returns>
    Task<IEnumerable<string>> GetClientListAsync(UserSession session);
}