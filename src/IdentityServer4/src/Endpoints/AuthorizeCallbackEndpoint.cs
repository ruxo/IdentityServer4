// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Immutable;
using System.Net;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Endpoints;

class AuthorizeCallbackEndpoint : AuthorizeEndpointBase
{
    readonly IConsentMessageStore consentResponseStore;
    readonly IAuthorizationParametersMessageStore? authorizationParametersMessageStore;

    public AuthorizeCallbackEndpoint(
        IEventService                          events,
        ILogger<AuthorizeCallbackEndpoint>     logger,
        IdentityServerOptions                  options,
        IAuthorizeRequestValidator             validator,
        IAuthorizeInteractionResponseGenerator interactionGenerator,
        IAuthorizeResponseGenerator            authorizeResponseGenerator,
        IUserSession                           userSession,
        IConsentMessageStore                   consentResponseStore,
        IAuthorizationParametersMessageStore?  authorizationParametersMessageStore = null)
        : base(events, logger, options, validator, interactionGenerator, authorizeResponseGenerator, userSession)
    {
        this.consentResponseStore                = consentResponseStore;
        this.authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public override async Task<Unit> HandleRequest(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            Logger.LogWarning("Invalid HTTP method for authorize endpoint");
            return context.ReturnStatusCode(HttpStatusCode.MethodNotAllowed);
        }

        Logger.LogDebug("Start authorize callback request");

        var parameters = context.Request.Query.ToImmutableDictionary();
        if (authorizationParametersMessageStore != null)
        {
            var messageStoreId = parameters[Constants.AuthorizationParamsStore.MessageStoreIdParameterName];
            var entry = await authorizationParametersMessageStore.ReadAsync(messageStoreId);
            parameters = entry.Data.ToApiParameters();

            await authorizationParametersMessageStore.DeleteAsync(messageStoreId);
        }

        var user = await UserSession.GetUserAsync();
        var consentRequest = new ConsentRequest(parameters, user.GetRequiredSubjectId());
        var consent = await consentResponseStore.ReadAsync(consentRequest.Id);

        try
        {
            await ProcessAuthorizeRequestAsync(parameters, user, consent.Get(c => c.Data));
        }
        finally
        {
            if (consent.IsSome) await consentResponseStore.DeleteAsync(consentRequest.Id);
        }
        return Unit.Default;
    }
}