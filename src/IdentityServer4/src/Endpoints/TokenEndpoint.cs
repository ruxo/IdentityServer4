// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Endpoints;

/// <summary>
/// The token endpoint
/// </summary>
/// <seealso cref="IdentityServer4.Hosting.IEndpointHandler" />
class TokenEndpoint : IEndpointHandler
{
    readonly IClientSecretValidator _clientValidator;
    readonly ITokenRequestValidator _requestValidator;
    readonly ITokenResponseGenerator _responseGenerator;
    readonly IEventService _events;
    readonly ILogger _logger;

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
        _clientValidator   = clientValidator;
        _requestValidator  = requestValidator;
        _responseGenerator = responseGenerator;
        _events            = events;
        _logger            = logger;
    }

    /// <summary>
    /// Processes the request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns></returns>
    public async Task HandleRequest(HttpContext context)
    {
        _logger.LogTrace("Processing token request");

        // validate HTTP
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasApplicationFormContentType())
        {
            _logger.LogWarning("Invalid HTTP request for token endpoint");
            return Error(OidcConstants.TokenErrors.InvalidRequest);
        }

        return await ProcessTokenRequestAsync(context);
    }

    async Task<IEndpointResult> ProcessTokenRequestAsync(HttpContext context)
    {
        _logger.LogDebug("Start token request");

        // validate client
        var clientResult = await _clientValidator.ValidateAsync(context);

        if (clientResult.IsLeft)
            return Error(OidcConstants.TokenErrors.InvalidClient);

        // validate request
        var form = (await context.Request.ReadFormAsync()).ToNameValueDictionary();
        _logger.LogTrace("Calling into token request validator: {Type}", _requestValidator.GetType().FullName);
        var result = await _requestValidator.ValidateRequestAsync(form, clientResult.GetRight());

        if (result.IsLeft) {
            var er = result.GetLeft();
            await _events.RaiseAsync(TokenIssuedFailureEvent.Create(er));
            return Error(er.Error, er.ErrorDescription, er.CustomResponse);
        }
        var requestResult = result.GetRight();

        // create response
        _logger.LogTrace("Calling into token request response generator: {Type}", _responseGenerator.GetType().FullName);
        var response = await _responseGenerator.ProcessAsync(requestResult);

        await _events.RaiseAsync(TokenIssuedSuccessEvent.Create(response, requestResult));
        LogTokens(response, requestResult);

        // return result
        _logger.LogDebug("Token request success");
        return new TokenResult(response);
    }

    static TokenErrorResult Error(string error, string? errorDescription = null, Dictionary<string, object>? custom = null) =>
        new(new(error, errorDescription, custom));

    void LogTokens(TokenResponse response, TokenRequestValidationResult requestResult) {
        var client = requestResult.ValidatedRequest.ValidatedClient.Get(c => c.Client);
        var clientId = $"{client.ClientId} ({client.ClientName ?? "no name set"})";
        var subjectId = requestResult.ValidatedRequest.Subject.Get().GetSubjectId();

        if (response.IdentityToken.IsSome)
            _logger.LogTrace("Identity token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.IdentityToken.Get());
        if (response.RefreshToken.IsSome)
            _logger.LogTrace("Refresh token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.RefreshToken.Get());

        _logger.LogTrace("Access token issued for {ClientId} / {SubjectId}: {Token}", clientId, subjectId, response.AccessToken);
    }
}