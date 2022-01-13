using System;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services;

/// <summary>
/// Cookie-based session implementation
/// </summary>
/// <seealso cref="IdentityServer4.Services.IUserSession" />
public sealed class DefaultUserSession : IUserSession
{
    /// <summary>
    /// The HTTP context accessor
    /// </summary>
    readonly IHttpContextAccessor httpContextAccessor;

    /// <summary>
    /// The handlers
    /// </summary>
    readonly IAuthenticationHandlerProvider handlers;

    /// <summary>
    /// The options
    /// </summary>
    readonly IdentityServerOptions options;

    /// <summary>
    /// The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    /// Gets the HTTP context.
    /// </summary>
    /// <value>
    /// The HTTP context.
    /// </value>
    HttpContext HttpContext => httpContextAccessor.HttpContext!;

    /// <summary>
    /// Gets the name of the check session cookie.
    /// </summary>
    /// <value>
    /// The name of the check session cookie.
    /// </value>
    string CheckSessionCookieName => options.Authentication.CheckSessionCookieName;

    /// <summary>
    /// Gets the domain of the check session cookie.
    /// </summary>
    /// <value>
    /// The domain of the check session cookie.
    /// </value>
    string CheckSessionCookieDomain => options.Authentication.CheckSessionCookieDomain;

    /// <summary>
    /// Gets the SameSite mode of the check session cookie.
    /// </summary>
    /// <value>
    /// The SameSite mode of the check session cookie.
    /// </value>
    SameSiteMode CheckSessionCookieSameSiteMode => options.Authentication.CheckSessionCookieSameSiteMode;

    Option<UserSession> currentSession;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultUserSession"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">The HTTP context accessor.</param>
    /// <param name="handlers">The handlers.</param>
    /// <param name="options">The options.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="logger">The logger.</param>
    public DefaultUserSession(IHttpContextAccessor httpContextAccessor,
                              IAuthenticationHandlerProvider handlers,
                              IdentityServerOptions options,
                              ISystemClock clock,
                              ILogger<DefaultUserSession> logger) {
        this.httpContextAccessor = httpContextAccessor;
        this.handlers = handlers;
        this.options = options;
        this.clock = clock;
        this.logger = logger;
    }

    // we need this helper (and can't call HttpContext.AuthenticateAsync) so we don't run
    // claims transformation when we get the principal. this also ensures that we don't
    // re-issue a cookie that includes the claims from claims transformation.
    //
    // also, by caching the _principal/_properties it allows someone to issue a new
    // cookie (via HttpContext.SignInAsync) and we'll use those new values, rather than
    // just reading the incoming cookie
    //
    // this design requires this to be in DI as scoped

    /// <summary>
    /// Authenticates the authentication cookie for the current HTTP request and caches the user and properties results.
    /// </summary>
    public async ValueTask<UserSession> GetCurrentSession() {
        if (currentSession.IsNone)
            currentSession = await GetCurrentSessionNoCache();
        return currentSession.Get();
    }

    /// <summary>
    /// Creates a session identifier for the signin context and issues the session id cookie.
    /// </summary>
    /// <param name="principal"></param>
    /// <param name="properties"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    /// principal
    /// or
    /// properties
    /// </exception>
    public async Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties) {
        var currentSubjectId = await GetUserAsync().Map(u => u.GetSubjectId());
        var newSubjectId = principal.GetSubjectId();

        if (currentSubjectId != newSubjectId || properties.GetSessionId().IsNone )
            properties.SetSessionId(CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex));

        var sid = properties.GetSessionId().Get();
        IssueSessionIdCookie(sid);

        currentSession = new UserSession(principal, properties);

        return sid;
    }

    async Task<UserSession> GetCurrentSessionNoCache() {
        var scheme = await HttpContext.GetCookieAuthenticationSchemeAsync();

        var handler = await handlers.GetHandlerAsync(HttpContext, scheme);
        if (handler == null)
            throw new InvalidOperationException($"No authentication handler is configured to authenticate for the scheme: {scheme}");

        var result = await handler.AuthenticateAsync();
        return new(result.Principal ?? new ClaimsPrincipal(new ClaimsIdentity(string.Empty)),
                   result.Properties ?? new AuthenticationProperties());
    }

    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    /// <returns></returns>
    public ValueTask<ClaimsPrincipal> GetUserAsync() => GetCurrentSession().Map(session => session.Subject);

    /// <summary>
    /// Gets the current session identifier.
    /// </summary>
    /// <returns></returns>
    public ValueTask<Option<string>> GetSessionIdAsync() => GetCurrentSession().Map(session => session.Properties.GetSessionId());

    /// <summary>
    /// Ensures the session identifier cookie asynchronous.
    /// </summary>
    /// <returns></returns>
    public async Task EnsureSessionIdCookieAsync()
    {
        var sid = await GetSessionIdAsync();
        if (sid.IsSome)
            IssueSessionIdCookie(sid.Get());
        else
            await RemoveSessionIdCookieAsync();
    }

    /// <summary>
    /// Removes the session identifier cookie.
    /// </summary>
    /// <returns></returns>
    public Task RemoveSessionIdCookieAsync()
    {
        if (HttpContext.Request.Cookies.ContainsKey(CheckSessionCookieName))
        {
            // only remove it if we have it in the request
            var opt = CreateSessionIdCookieOptions();
            opt.Expires = clock.UtcNow.UtcDateTime.AddYears(-1);

            HttpContext.Response.Cookies.Append(CheckSessionCookieName, ".", opt);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates the options for the session cookie.
    /// </summary>
    public CookieOptions CreateSessionIdCookieOptions() =>
        new(){
            HttpOnly    = false,
            Secure      = HttpContext.Request.IsHttps,
            Path        = HttpContext.GetIdentityServerBasePath().CleanUrlPath(),
            IsEssential = true,
            Domain      = CheckSessionCookieDomain,
            SameSite    = CheckSessionCookieSameSiteMode
        };

    /// <summary>
    /// Issues the cookie that contains the session id.
    /// </summary>
    /// <param name="sid"></param>
    public void IssueSessionIdCookie(string sid)
    {
        if (options.Endpoints.EnableCheckSessionEndpoint && HttpContext.Request.Cookies[CheckSessionCookieName] != sid)
            HttpContext.Response.Cookies.Append(options.Authentication.CheckSessionCookieName, sid, CreateSessionIdCookieOptions());
    }

    /// <summary>
    /// Adds a client to the list of clients the user has signed into during their session.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">clientId</exception>
    public async Task AddClientIdAsync(UserSession session, string clientId)
    {
        var (_, properties) = session;
        var clientIds = properties.GetClientList();
        if (!clientIds.Contains(clientId)) {
            properties.AddClientId(clientId);
            await UpdateSessionCookie(session);
        }
    }

    /// <summary>
    /// Gets the list of clients the user has signed into during their session.
    /// </summary>
    /// <param name="session"></param>
    /// <returns></returns>
    public async Task<IEnumerable<string>> GetClientListAsync(UserSession session)
    {
        try {
            return session.Properties.GetClientList();
        }
        catch (Exception ex) {
            logger.LogError(ex, "Error decoding client list");
            // clear so we don't keep failing
            session.Properties.RemoveClientList();
            await UpdateSessionCookie(session);
            return Enumerable.Empty<string>();
        }
    }

    // client list helpers
    async Task UpdateSessionCookie(UserSession session) {
        currentSession = session;
        var (principal, properties) = session;

        if (!principal.IsAuthenticated()) throw new InvalidOperationException("User is not currently authenticated");

        var scheme = await HttpContext.GetCookieAuthenticationSchemeAsync();
        await HttpContext.SignInAsync(scheme, principal, properties);
    }
}