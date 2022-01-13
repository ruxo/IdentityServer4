// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Immutable;
using IdentityModel;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Endpoints;

/// <summary>
/// The token endpoint
/// </summary>
/// <seealso cref="IdentityServer4.Hosting.IEndpointHandler" />
class TokenEndpoint : IEndpointHandler
{
    readonly IClientSecretValidator clientValidator;
    readonly ITokenRequestValidator requestValidator;
    readonly ITokenResponseGenerator responseGenerator;
    readonly IEventService events;
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenEndpoint" /> class.
    /// </summary>
    /// <param name="clientValidator">The client validator.</param>
    /// <param name="requestValidator">The request validator.</param>
    /// <param name="responseGenerator">The response generator.</param>
    /// <param name="events">The events.</param>
    /// <param name="logger">The logger.</param>
    public TokenEndpoint(
        IClientSecretValidator  clientValidator,
        ITokenRequestValidator  requestValidator,
        ITokenResponseGenerator responseGenerator,
        IEventService           events,
        ILogger<TokenEndpoint>  logger)
    {
        this.clientValidator   = clientValidator;
        this.requestValidator  = requestValidator;
        this.responseGenerator = responseGenerator;
        this.events            = events;
        this.logger            = logger;
    }

    /// <summary>
    /// Processes the request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns></returns>
    public async Task<Either<ErrorInfo, Unit>> HandleRequest(HttpContext context)
    {
        logger.LogTrace("Processing token request");

        // validate HTTP
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasApplicationFormContentType())
            return await ProcessTokenRequestAsync(context);
        logger.LogWarning("Invalid HTTP request for token endpoint");
        return new ErrorInfo(OidcConstants.TokenErrors.InvalidRequest);
    }

    async ValueTask<Either<ErrorInfo, Unit>> ProcessTokenRequestAsync(HttpContext context)
    {
        logger.LogDebug("Start token request");

        // validate client
        var verifiedResult = await clientValidator.GetVerifiedClient(context);

        if (verifiedResult.IsLeft)
            return verifiedResult.GetLeft();

        // validate request
        var parameters = (await context.Request.ReadFormAsync()).ToImmutableDictionary();
        logger.LogTrace("Calling into token request validator: {Type}", requestValidator.GetType().FullName);
        var result = await requestValidator.ValidateRequestAsync(parameters, verifiedResult.GetRight());

        if (result.IsLeft) {
            var er = result.GetLeft();
            await events.RaiseAsync(TokenIssuedFailureEvent.Create(er));
            return new ErrorInfo(er.Error, er.ErrorDescription, er.CustomResponse);
        }
        var requestResult = result.GetRight();

        // create response
        logger.LogTrace("Calling into token request response generator: {Type}", responseGenerator.GetType().FullName);
        var response = await responseGenerator.ProcessAsync(requestResult);

        await events.RaiseAsync(TokenIssuedSuccessEvent.Create(response, requestResult));
        LogTokens(response, requestResult);

        // return result
        logger.LogDebug("Token request success");
        return new TokenResult(response);
    }

    static TokenErrorResult Error(string error, string? errorDescription = null, Dictionary<string, object>? custom = null) =>
        new(new(error, errorDescription, custom));

    void LogTokens(TokenResponse response, TokenRequestValidationResult requestResult) {
        var client = requestResult.ValidatedRequest.ValidatedClient.Get(c => c.Client);
        var clientId = $"{client.ClientId} ({client.ClientName ?? "no name set"})";
        var subjectId = requestResult.ValidatedRequest.Subject.Get().GetSubjectId();

        if (response.IdentityToken.IsSome)
            logger.LogTrace("Identity token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.IdentityToken.Get());
        if (response.RefreshToken.IsSome)
            logger.LogTrace("Refresh token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.RefreshToken.Get());

        logger.LogTrace("Access token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.AccessToken);
    }
}