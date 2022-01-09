// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Immutable;
using System.Net;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace IdentityServer4.Endpoints;

class AuthorizeEndpoint : AuthorizeEndpointBase
{
    public AuthorizeEndpoint(ILogger logger, IdentityServerOptions options, IAuthorizationCodeStore authorizationCodeStore, IClientStore clientStore, IConsentService consentService, IEventService events, IKeyMaterialService keyMaterialService, IProfileService profileService, IRedirectUriValidator uriValidator, IResourceValidator resourceValidator, IScopeParser scopeParser, ISystemClock clock, IUserSession userSession, IAuthorizationParametersMessageStore? authorizationParametersMessageStore) : base(logger, options, authorizationCodeStore, clientStore, consentService, events, keyMaterialService, profileService, uriValidator, resourceValidator, scopeParser, clock, userSession, authorizationParametersMessageStore) { }

    public override async Task<Unit> HandleRequest(HttpContext context)
    {
        Logger.LogDebug("Start authorize request");

        ImmutableDictionary<string,StringValues> values;

        if (HttpMethods.IsGet(context.Request.Method))
            values = context.Request.Query.ToImmutableDictionary();
        else if (HttpMethods.IsPost(context.Request.Method))
        {
            if (!context.Request.HasApplicationFormContentType())
                return context.ReturnStatusCode(HttpStatusCode.UnsupportedMediaType);

            values = context.Request.Form.ToImmutableDictionary();
        }
        else
            return context.ReturnStatusCode(HttpStatusCode.MethodNotAllowed);

        var user = await UserSession.GetCurrentSession();
        var renderer = await ProcessAuthorizeRequestAsync(values, user, None);
        return await renderer(context);
    }
}