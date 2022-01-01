// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using System.Text.Encodings.Web;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.ResponseHandling.Models;

namespace IdentityServer4.Endpoints.Results;

[Obsolete]
class AuthorizeResult : IEndpointResult
{
    public AuthorizeResponse Response { get; }

    public AuthorizeResult(AuthorizeResponse response)
    {
        Response = response ?? throw new ArgumentNullException(nameof(response));
    }

    internal AuthorizeResult(
        AuthorizeResponse response,
        IdentityServerOptions options,
        IUserSession userSession,
        IMessageStore<ErrorMessage> errorMessageStore,
        ISystemClock clock)
        : this(response)
    {
        this.options = options;
        this.userSession = userSession;
        this.errorMessageStore = errorMessageStore;
        this.clock = clock;
    }

    IdentityServerOptions options;
    IUserSession userSession;
    IMessageStore<ErrorMessage> errorMessageStore;
    ISystemClock clock;

    void Init(HttpContext context)
    {
        options = options ?? context.RequestServices.GetRequiredService<IdentityServerOptions>();
        userSession = userSession ?? context.RequestServices.GetRequiredService<IUserSession>();
        errorMessageStore = errorMessageStore ?? context.RequestServices.GetRequiredService<IMessageStore<ErrorMessage>>();
        clock = clock ?? context.RequestServices.GetRequiredService<ISystemClock>();
    }

    public async Task ExecuteAsync(HttpContext context)
    {
        Init(context);

        if (Response.IsError)
            await ProcessErrorAsync(context);
        else
            await ProcessResponseAsync(context);
    }

    async Task ProcessErrorAsync(HttpContext context)
    {
        // these are the conditions where we can send a response
        // back directly to the client, otherwise we're only showing the error UI
        var isSafeError =
            Response.Error is OidcConstants.AuthorizeErrors.AccessDenied or OidcConstants.AuthorizeErrors.AccountSelectionRequired or OidcConstants.AuthorizeErrors.LoginRequired
                or OidcConstants.AuthorizeErrors.ConsentRequired or OidcConstants.AuthorizeErrors.InteractionRequired;

        if (isSafeError)
        {
            // this scenario we can return back to the client
            await ProcessResponseAsync(context);
        }
        else
        {
            // we now know we must show error page
            await RedirectToErrorPageAsync(context);
        }
    }

    protected async Task ProcessResponseAsync(HttpContext context)
    {
        if (!Response.IsError)
        {
            // success response -- track client authorization for sign-out
            //_logger.LogDebug("Adding client {0} to client list cookie for subject {1}", request.ClientId, request.Subject.GetSubjectId());
            await userSession.AddClientIdAsync(Response.Request.ClientId);
        }

        await RenderAuthorizeResponseAsync(context);
    }

    async Task RenderAuthorizeResponseAsync(HttpContext context)
    {
        if (Response.Request.ResponseMode == OidcConstants.ResponseModes.Query ||
            Response.Request.ResponseMode == OidcConstants.ResponseModes.Fragment)
        {
            context.Response.SetNoCache();
            context.Response.Redirect(BuildRedirectUri());
        }
        else if (Response.Request.ResponseMode == OidcConstants.ResponseModes.FormPost)
        {
            context.Response.SetNoCache();
            AddSecurityHeaders(context);
            await context.Response.WriteHtmlAsync(GetFormPostHtml());
        }
        else
        {
            //_logger.LogError("Unsupported response mode.");
            throw new InvalidOperationException("Unsupported response mode");
        }
    }

    void AddSecurityHeaders(HttpContext context)
    {
        context.Response.AddScriptCspHeaders(options.Csp, "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=");

        var referrerPolicy = "no-referrer";
        if (!context.Response.Headers.ContainsKey("Referrer-Policy"))
        {
            context.Response.Headers.Add("Referrer-Policy", referrerPolicy);
        }
    }

    string BuildRedirectUri()
    {
        var uri = Response.RedirectUri;
        var query = Response.ToNameValueCollection().ToQueryString();

        if (Response.Request.ResponseMode == OidcConstants.ResponseModes.Query)
        {
            uri = uri.AddQueryString(query);
        }
        else
        {
            uri = uri.AddHashFragment(query);
        }

        if (Response.IsError && !uri.Contains("#"))
        {
            // https://tools.ietf.org/html/draft-bradley-oauth-open-redirector-00
            uri += "#_=_";
        }

        return uri;
    }

    const string FormPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>";

    string GetFormPostHtml()
    {
        var html = FormPostHtml;

        var url = Response.Request.RedirectUri;
        url = HtmlEncoder.Default.Encode(url);
        html = html.Replace("{uri}", url);
        html = html.Replace("{body}", Response.ToNameValueCollection().ToFormPost());

        return html;
    }

    async Task RedirectToErrorPageAsync(HttpContext context)
    {
        var errorModel = new ErrorMessage
        {
            RequestId = context.TraceIdentifier,
            Error = Response.Error,
            ErrorDescription = Response.ErrorDescription,
            UiLocales = Response.Request?.UiLocales,
            DisplayMode = Response.Request?.DisplayMode,
            ClientId = Response.Request?.ClientId
        };

        if (Response.RedirectUri != null && Response.Request?.ResponseMode != null)
        {
            // if we have a valid redirect uri, then include it to the error page
            errorModel.RedirectUri = BuildRedirectUri();
            errorModel.ResponseMode = Response.Request.ResponseMode;
        }

        var message = Message.Create(errorModel, clock.UtcNow.UtcDateTime);
        var id = await errorMessageStore.WriteAsync(message);

        var url = options.UserInteraction.ErrorUrl.AddQueryString(options.UserInteraction.ErrorIdParameter, id);
        context.Response.RedirectToAbsoluteUrl(url);
    }
}