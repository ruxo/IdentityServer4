// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using IdentityServer4.Services;
using Microsoft.Extensions.Logging;
using IdentityServer4.Configuration.DependencyInjection;
using IdentityServer4.Extensions;
using System;
using IdentityModel;
using System.Linq;

namespace IdentityServer4.Hosting;

// this decorates the real authentication service to detect when the
// user is being signed in. this allows us to ensure the user has
// the claims needed for identity server to do its job. it also allows
// us to track signin/signout so we can issue/remove the session id
// cookie used for check session iframe for session management spec.
// finally, we track if signout is called to collaborate with the
// FederatedSignoutAuthenticationHandlerProvider for federated signout.
class IdentityServerAuthenticationService : IAuthenticationService
{
    readonly IAuthenticationService inner;
    readonly IAuthenticationSchemeProvider schemes;
    readonly ISystemClock clock;
    readonly IUserSession session;
    readonly ILogger<IdentityServerAuthenticationService> logger;

    public IdentityServerAuthenticationService(
        Decorator<IAuthenticationService> decorator,
        IAuthenticationSchemeProvider schemes,
        ISystemClock clock,
        IUserSession session,
        ILogger<IdentityServerAuthenticationService> logger)
    {
        inner = decorator.Instance;

        this.schemes = schemes;
        this.clock = clock;
        this.session = session;
        this.logger = logger;
    }

    public async Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        var defaultScheme = await schemes.GetDefaultSignInSchemeAsync();
        var cookieScheme = await context.GetCookieAuthenticationSchemeAsync();

        if (scheme == null && defaultScheme?.Name == cookieScheme || scheme == cookieScheme)
        {
            AugmentPrincipal(principal);

            properties ??= new();
            await session.CreateSessionIdAsync(principal, properties);
        }

        await inner.SignInAsync(context, scheme, principal, properties);
    }

    void AugmentPrincipal(ClaimsPrincipal principal)
    {
        logger.LogDebug("Augmenting SignInContext");

        AssertRequiredClaims(principal);
        AugmentMissingClaims(principal, clock.UtcNow.UtcDateTime);
    }

    public async Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        var defaultScheme = await schemes.GetDefaultSignOutSchemeAsync();
        var cookieScheme = await context.GetCookieAuthenticationSchemeAsync();

        if ((scheme == null && defaultScheme?.Name == cookieScheme) || scheme == cookieScheme)
        {
            // this sets a flag used by middleware to do post-signout work.
            context.SetSignOutCalled();
        }

        await inner.SignOutAsync(context, scheme, properties);
    }

    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
    {
        return inner.AuthenticateAsync(context, scheme);
    }

    public Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        return inner.ChallengeAsync(context, scheme, properties);
    }

    public Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        return inner.ForbidAsync(context, scheme, properties);
    }

    void AssertRequiredClaims(ClaimsPrincipal principal)
    {
        // for now, we don't allow more than one identity in the principal/cookie
        if (principal.Identities.Count() != 1) throw new InvalidOperationException("only a single identity supported");
        if (principal.FindFirst(JwtClaimTypes.Subject) == null) throw new InvalidOperationException("sub claim is missing");
    }

    void AugmentMissingClaims(ClaimsPrincipal principal, DateTime authTime)
    {
        var identity = principal.Identities.First();

        // ASP.NET Identity issues this claim type and uses the authentication middleware name
        // such as "Google" for the value. this code is trying to correct/convert that for
        // our scenario. IOW, we take their old AuthenticationMethod value of "Google"
        // and issue it as the idp claim. we then also issue a amr with "external"
        var amr = identity.FindFirst(ClaimTypes.AuthenticationMethod);
        if (amr != null &&
            identity.FindFirst(JwtClaimTypes.IdentityProvider) == null &&
            identity.FindFirst(JwtClaimTypes.AuthenticationMethod) == null)
        {
            logger.LogDebug("Removing amr claim with value: {value}", amr.Value);
            identity.RemoveClaim(amr);

            logger.LogDebug("Adding idp claim with value: {value}", amr.Value);
            identity.AddClaim(new Claim(JwtClaimTypes.IdentityProvider, amr.Value));

            logger.LogDebug("Adding amr claim with value: {value}", Constants.ExternalAuthenticationMethod);
            identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, Constants.ExternalAuthenticationMethod));
        }

        if (identity.FindFirst(JwtClaimTypes.IdentityProvider) == null)
        {
            logger.LogDebug("Adding idp claim with value: {value}", IdentityServerConstants.LocalIdentityProvider);
            identity.AddClaim(new Claim(JwtClaimTypes.IdentityProvider, IdentityServerConstants.LocalIdentityProvider));
        }

        if (identity.FindFirst(JwtClaimTypes.AuthenticationMethod) == null)
        {
            if (identity.FindFirst(JwtClaimTypes.IdentityProvider).Value == IdentityServerConstants.LocalIdentityProvider)
            {
                logger.LogDebug("Adding amr claim with value: {value}", OidcConstants.AuthenticationMethods.Password);
                identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, OidcConstants.AuthenticationMethods.Password));
            }
            else
            {
                logger.LogDebug("Adding amr claim with value: {value}", Constants.ExternalAuthenticationMethod);
                identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, Constants.ExternalAuthenticationMethod));
            }
        }

        if (identity.FindFirst(JwtClaimTypes.AuthenticationTime) == null)
        {
            var time = new DateTimeOffset(authTime).ToUnixTimeSeconds().ToString();

            logger.LogDebug("Adding auth_time claim with value: {value}", time);
            identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationTime, time, ClaimValueTypes.Integer64));
        }
    }
}