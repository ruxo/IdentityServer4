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

namespace IdentityServer4.Endpoints;

class AuthorizeCallbackEndpoint : AuthorizeEndpointBase
{
    readonly IUserSession userSession;
    readonly IConsentMessageStore consentResponseStore;
    readonly IAuthorizationParametersMessageStore? authorizationParametersMessageStore;

    /// <summary>
    /// ctor
    /// </summary>
    public AuthorizeCallbackEndpoint(ILogger logger, IdentityServerOptions options, IAuthorizationCodeStore authorizationCodeStore, IAuthContextParser contextParser,
                                     IClaimsService claimsService, IConsentMessageStore consentMessageStore, IConsentService consentService, IEventService events,
                                     IKeyMaterialService keyMaterialService,
                                     IMessageStore<ErrorMessage> errorMessageStore, IProfileService profileService, ISystemClock clock, ITokenService tokenService,
                                     ITokenCreationService tokenCreationService, IUserSession userSession,
                                     IAuthorizationParametersMessageStore? authorizationParametersMessageStore) : base(logger,
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
        consentResponseStore = consentMessageStore;
        this.authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public override async Task<Either<ErrorInfo, Unit>> HandleRequest(HttpContext context)
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

        var user = await userSession.GetCurrentSession();
        var consentRequest = new ConsentRequest(parameters, user.AuthenticatedUser.SubjectId);
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