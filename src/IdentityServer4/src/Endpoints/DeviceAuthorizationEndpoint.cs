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

namespace IdentityServer4.Endpoints
{
    /// <summary>
    /// The device authorization endpoint
    /// </summary>
    /// <seealso cref="IdentityServer4.Hosting.IEndpointHandler" />
    class DeviceAuthorizationEndpoint : IEndpointHandler
    {
        readonly IClientSecretValidator _clientValidator;
        readonly IDeviceAuthorizationRequestValidator _requestValidator;
        readonly IDeviceAuthorizationResponseGenerator _responseGenerator;
        readonly IEventService _events;
        readonly ILogger<DeviceAuthorizationEndpoint> _logger;

        public DeviceAuthorizationEndpoint(
            IClientSecretValidator clientValidator,
            IDeviceAuthorizationRequestValidator requestValidator,
            IDeviceAuthorizationResponseGenerator responseGenerator,
            IEventService events,
            ILogger<DeviceAuthorizationEndpoint> logger)
        {
            _clientValidator = clientValidator;
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
        /// <exception cref="System.NotImplementedException"></exception>
        public async Task HandleRequest(HttpContext context)
        {
            _logger.LogTrace("Processing device authorize request");

            // validate HTTP
            if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasApplicationFormContentType())
            {
                _logger.LogWarning("Invalid HTTP request for device authorize endpoint");
                return Error(OidcConstants.TokenErrors.InvalidRequest);
            }

            return await ProcessDeviceAuthorizationRequestAsync(context);
        }

        async Task<IEndpointResult> ProcessDeviceAuthorizationRequestAsync(HttpContext context)
        {
            _logger.LogDebug("Start device authorize request");

            var cr = await _clientValidator.GetVerifiedClient(context);
            if (cr.IsLeft) return Error(OidcConstants.TokenErrors.InvalidClient);
            var clientResult = cr.GetRight();

            var form = (await context.Request.ReadFormAsync()).ToNameValueDictionary();
            var request = await _requestValidator.ValidateAsync(form, clientResult);

            if (request.IsLeft) {
                var error = request.GetLeft();
                await _events.RaiseAsync(DeviceAuthorizationFailureEvent.Create(error));
                return Error(error.Error, error.ErrorDescription);
            }

            var baseUrl = context.GetIdentityServerBaseUrl().EnsureTrailingSlash();

            _logger.LogTrace("Calling into device authorize response generator: {Type}", _responseGenerator.GetType().FullName);
            var requestResult = request.GetRight();
            var response = await _responseGenerator.ProcessAsync(requestResult, baseUrl);

            await _events.RaiseAsync(DeviceAuthorizationSuccessEvent.Create(requestResult));

            _logger.LogDebug("Device authorize request success");
            return new DeviceAuthorizationResult(response);
        }

        TokenErrorResult Error(string error, string? errorDescription = null, Dictionary<string, object>? custom = null) {
            _logger.LogError("Device authorization error: {Error}:{ErrorDescriptions}", error, errorDescription ?? "-no message-");

            return new(new(error, errorDescription, custom));
        }
    }
}