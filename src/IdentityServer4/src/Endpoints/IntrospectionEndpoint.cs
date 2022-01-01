// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Validation;
using IdentityServer4.ResponseHandling;
using Microsoft.Extensions.Logging;
using IdentityServer4.Hosting;
using IdentityServer4.Endpoints.Results;
using Microsoft.AspNetCore.Http;
using System.Net;
using IdentityServer4.Services;
using IdentityServer4.Events;
using IdentityServer4.Extensions;

namespace IdentityServer4.Endpoints
{
    /// <summary>
    /// Introspection endpoint
    /// </summary>
    /// <seealso cref="IdentityServer4.Hosting.IEndpointHandler" />
    class IntrospectionEndpoint : IEndpointHandler
    {
        readonly IIntrospectionResponseGenerator _responseGenerator;
        readonly IEventService _events;
        readonly ILogger _logger;
        readonly IIntrospectionRequestValidator _requestValidator;
        readonly IApiSecretValidator _apiSecretValidator;

        /// <summary>
        /// Initializes a new instance of the <see cref="IntrospectionEndpoint" /> class.
        /// </summary>
        /// <param name="apiSecretValidator">The API secret validator.</param>
        /// <param name="requestValidator">The request validator.</param>
        /// <param name="responseGenerator">The generator.</param>
        /// <param name="events">The events.</param>
        /// <param name="logger">The logger.</param>
        public IntrospectionEndpoint(
            IApiSecretValidator apiSecretValidator,
            IIntrospectionRequestValidator requestValidator,
            IIntrospectionResponseGenerator responseGenerator,
            IEventService events,
            ILogger<IntrospectionEndpoint> logger)
        {
            _apiSecretValidator = apiSecretValidator;
            _requestValidator = requestValidator;
            _responseGenerator = responseGenerator;
            _events = events;
            _logger = logger;
        }

        /// <summary>
        /// Processes the request.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <returns></returns>
        public async Task HandleRequest(HttpContext context)
        {
            _logger.LogTrace("Processing introspection request");

            // validate HTTP
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                _logger.LogWarning("Introspection endpoint only supports POST requests");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            if (!context.Request.HasApplicationFormContentType())
            {
                _logger.LogWarning("Invalid media type for introspection endpoint");
                return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            return await ProcessIntrospectionRequestAsync(context);
        }

        async Task<IEndpointResult> ProcessIntrospectionRequestAsync(HttpContext context)
        {
            _logger.LogDebug("Starting introspection request");

            // caller validation
            var apiResult = await _apiSecretValidator.ValidateAsync(context);
            if (apiResult.IsLeft)
            {
                _logger.LogError("API unauthorized to call introspection endpoint. aborting");
                return new StatusCodeResult(HttpStatusCode.Unauthorized);
            }
            var apiResource = apiResult.GetRight();

            var body = await context.Request.ReadFormAsync();
            if (body.Count == 0)
            {
                _logger.LogError("Malformed request body. aborting");
                await _events.RaiseAsync(new TokenIntrospectionFailureEvent(apiResource.Name, "Malformed request body"));

                return new StatusCodeResult(HttpStatusCode.BadRequest);
            }

            // request validation
            _logger.LogTrace("Calling into introspection request validator: {Type}", _requestValidator.GetType().FullName);
            var validationResult = await _requestValidator.ValidateAsync(body.ToNameValueDictionary(), apiResource);
            if (validationResult.IsLeft)
            {
                var error = validationResult.GetLeft().Error;
                LogFailure(error, apiResource.Name);
                await _events.RaiseAsync(new TokenIntrospectionFailureEvent(apiResource.Name, error));

                return new BadRequestResult(error);
            }

            // response generation
            _logger.LogTrace("Calling into introspection response generator: {Type}", _responseGenerator.GetType().FullName);
            var response = await _responseGenerator.ProcessAsync(apiResource, validationResult.GetRight());

            // render result
            _logger.LogInformation("Success token introspection for API name: {ApiName}", apiResource.Name);
            return new IntrospectionResult(response);
        }

        void LogFailure(string error, string apiName)
        {
            _logger.LogError("Failed token introspection: {Error}, for API name: {ApiName}", error, apiName);
        }
    }
}