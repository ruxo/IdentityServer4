// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using System;
using Microsoft.Extensions.Logging;
using System.Linq;
using IdentityServer4.Models.Messages;
using IdentityServer4.Services.Default;
using Microsoft.AspNetCore.Authentication;

namespace IdentityServer4.Services;

class DefaultIdentityServerInteractionService : IIdentityServerInteractionService
{
    readonly ISystemClock clock;
    readonly IHttpContextAccessor context;
    readonly IMessageStore<LogoutMessage> logoutMessageStore;
    readonly IMessageStore<ErrorMessage> errorMessageStore;
    readonly IConsentMessageStore consentMessageStore;
    readonly IPersistedGrantService grants;
    readonly IUserSession userSession;
    readonly ILogger logger;
    readonly ReturnUrlParser returnUrlParser;

    public DefaultIdentityServerInteractionService(
        ISystemClock clock,
        IHttpContextAccessor context,
        IMessageStore<LogoutMessage> logoutMessageStore,
        IMessageStore<ErrorMessage> errorMessageStore,
        IConsentMessageStore consentMessageStore,
        IPersistedGrantService grants,
        IUserSession userSession,
        ReturnUrlParser returnUrlParser,
        ILogger<DefaultIdentityServerInteractionService> logger)
    {
        this.clock = clock;
        this.context = context;
        this.logoutMessageStore = logoutMessageStore;
        this.errorMessageStore = errorMessageStore;
        this.consentMessageStore = consentMessageStore;
        this.grants = grants;
        this.userSession = userSession;
        this.returnUrlParser = returnUrlParser;
        this.logger = logger;
    }

    public async Task<AuthorizationRequest> GetAuthorizationContextAsync(string returnUrl)
    {
        var result = await returnUrlParser.ParseAsync(returnUrl);

        if (result != null)
        {
            logger.LogTrace("AuthorizationRequest being returned");
        }
        else
        {
            logger.LogTrace("No AuthorizationRequest being returned");
        }

        return result;
    }

    public async Task<LogoutRequest> GetLogoutContextAsync(string logoutId)
    {
        var msg = await logoutMessageStore.ReadAsync(logoutId);
        var iframeUrl = await context.HttpContext.GetIdentityServerSignoutFrameCallbackUrlAsync(msg?.Data);
        return new LogoutRequest(iframeUrl, msg?.Data);
    }

    public async Task<Option<string>> CreateLogoutContextAsync()
    {
        var user = await userSession.GetUserAsync();
        var clientIds = Seq(await userSession.GetClientListAsync(TODO));
        if (!user.IsSome || !clientIds.Any()) return None;

        var sid = await userSession.GetSessionIdAsync();
        var msg = Message.Create(new LogoutMessage{
            SubjectId = user.Get().GetSubjectId(),
            SessionId = sid.Get(),
            ClientIds = clientIds.ToArray()
        }, clock.UtcNow.UtcDateTime);
        return await logoutMessageStore.WriteAsync(msg);
    }

    public async Task<ErrorMessage> GetErrorContextAsync(string errorId)
    {
        if (errorId != null)
        {
            var result = await errorMessageStore.ReadAsync(errorId);
            var data = result?.Data;
            if (data != null)
            {
                logger.LogTrace("Error context loaded");
            }
            else
            {
                logger.LogTrace("No error context found");
            }
            return data;
        }

        logger.LogTrace("No error context found");

        return null;
    }

    public async Task GrantConsentAsync(AuthorizationRequest request, ConsentResponse consent, string subject = null)
    {
        if (subject == null)
        {
            var user = await userSession.GetUserAsync();
            subject = user?.GetRequiredSubjectId();
        }

        if (subject == null && consent.Granted)
        {
            throw new ArgumentNullException(nameof(subject), "User is not currently authenticated, and no subject id passed");
        }

        var consentRequest = new ConsentRequest(request, subject);
        await consentMessageStore.WriteAsync(consentRequest.Id, Message.Create(consent, clock.UtcNow.UtcDateTime));
    }

    public Task DenyAuthorizationAsync(AuthorizationRequest request, AuthorizationError error, string errorDescription = null)
    {
        var response = new ConsentResponse
        {
            Error = error,
            ErrorDescription = errorDescription
        };
        return GrantConsentAsync(request, response);
    }

    public bool IsValidReturnUrl(string returnUrl)
    {
        var result = returnUrlParser.IsValidReturnUrl(returnUrl);

        if (result)
        {
            logger.LogTrace("IsValidReturnUrl true");
        }
        else
        {
            logger.LogTrace("IsValidReturnUrl false");
        }

        return result;
    }

    public async Task<IEnumerable<Grant>> GetAllUserGrantsAsync()
    {
        var user = await userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetRequiredSubjectId();
            return await grants.GetAllGrantsAsync(subject);
        }

        return Enumerable.Empty<Grant>();
    }

    public async Task RevokeUserConsentAsync(string clientId)
    {
        var user = await userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetRequiredSubjectId();
            await grants.RemoveAllGrantsAsync(subject, clientId);
        }
    }

    public async Task RevokeTokensForCurrentSessionAsync()
    {
        var user = await userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetRequiredSubjectId();
            var sessionId = await userSession.GetSessionIdAsync();
            await grants.RemoveAllGrantsAsync(subject, sessionId: sessionId);
        }
    }
}