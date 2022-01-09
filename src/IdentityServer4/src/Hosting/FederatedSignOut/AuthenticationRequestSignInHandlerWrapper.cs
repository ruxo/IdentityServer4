// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.Hosting.FederatedSignOut;

class AuthenticationRequestSignInHandlerWrapper : AuthenticationRequestSignOutHandlerWrapper, IAuthenticationSignInHandler
{
    readonly IAuthenticationSignInHandler inner;

    public AuthenticationRequestSignInHandlerWrapper(IAuthenticationSignInHandler inner, IHttpContextAccessor httpContextAccessor)
        : base(inner, httpContextAccessor)
    {
        this.inner = inner;
    }

    public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        return inner.SignInAsync(user, properties);
    }
}