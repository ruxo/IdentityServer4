// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Immutable;
using System.Net;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace IdentityServer4.Endpoints;

class AuthorizeEndpoint : AuthorizeEndpointBase
{
    readonly IUserSession userSession;

    public AuthorizeEndpoint(ILogger logger, IdentityServerOptions options, IAuthorizationCodeStore authorizationCodeStore, IAuthContextParser contextParser,
                             IClaimsService claimsService, IConsentService consentService, IEventService events, IKeyMaterialService keyMaterialService,
                             IMessageStore<ErrorMessage> errorMessageStore, IProfileService profileService, ISystemClock clock, ITokenService tokenService,
                             ITokenCreationService tokenCreationService, IUserSession userSession, IAuthorizationParametersMessageStore? authorizationParametersMessageStore) :
        base(logger,
             options,
             authorizationCodeStore,
             contextParser,
             claimsService,
             consentService,
             events,
             keyMaterialService,
             errorMessageStore,
             profileService,
             clock,
             tokenService,
             tokenCreationService,
             userSession,
             authorizationParametersMessageStore) {
        this.userSession = userSession;
    }

    public override async Task<Either<ErrorInfo, Unit>> HandleRequest(HttpContext context)
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

        var session = await userSession.GetCurrentSession();
        var renderer = await ProcessAuthorizeRequestAsync(values, session, None);
        return await renderer(context);
    }
}