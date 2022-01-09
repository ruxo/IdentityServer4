// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Specialized;
using System.Net;
using System.Threading.Tasks;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Endpoints;

class EndSessionEndpoint : IEndpointHandler
{
    readonly IEndSessionRequestValidator endSessionRequestValidator;

    readonly ILogger logger;

    readonly IUserSession userSession;

    public EndSessionEndpoint(
        IEndSessionRequestValidator endSessionRequestValidator,
        IUserSession userSession,
        ILogger<EndSessionEndpoint> logger)
    {
        this.endSessionRequestValidator = endSessionRequestValidator;
        this.userSession = userSession;
        this.logger = logger;
    }

    public async Task HandleRequest(HttpContext context)
    {
        Dictionary<string,string> parameters;
        if (HttpMethods.IsGet(context.Request.Method))
        {
            parameters = context.Request.Query.ToNameValueDictionary();
        }
        else if (HttpMethods.IsPost(context.Request.Method))
        {
            parameters = (await context.Request.ReadFormAsync()).ToNameValueDictionary();
        }
        else
        {
            logger.LogWarning("Invalid HTTP method for end session endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var user = await userSession.GetUserAsync();

        logger.LogDebug("Processing signout request for {subjectId}", user.GetRequiredSubjectId() ?? "anonymous");

        var result = await endSessionRequestValidator.ValidateAsync(parameters, user);

        if (result.IsError)
        {
            logger.LogError("Error processing end session request {error}", result.Error);
        }
        else
        {
            logger.LogDebug("Success validating end session request from {clientId}", result.ValidatedRequest?.Client?.ClientId);
        }

        return new EndSessionResult(result);
    }
}