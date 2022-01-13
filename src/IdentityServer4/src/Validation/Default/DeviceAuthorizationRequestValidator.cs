// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Diagnostics;
using System.Linq;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Logging;
using IdentityServer4.Models;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

class DeviceAuthorizationRequestValidator : IDeviceAuthorizationRequestValidator
{
    readonly IdentityServerOptions options;
    readonly IResourceValidator resourceValidator;
    readonly ILogger<DeviceAuthorizationRequestValidator> logger;

    public DeviceAuthorizationRequestValidator(
        IdentityServerOptions                        options,
        IResourceValidator                           resourceValidator,
        ILogger<DeviceAuthorizationRequestValidator> logger)
    {
        this.options           = options;
        this.resourceValidator = resourceValidator;
        this.logger            = logger;
    }

    public async Task<Either<DeviceAuthorizationRequestValidationError, DeviceAuthorizationRequestValidationResult>> ValidateAsync(Dictionary<string,string> parameters, VerifiedClient verifiedClientValidationResult)
    {
        logger.LogDebug("Start device authorization request validation");

        var request = new ValidatedDeviceAuthorizationRequest
        {
            Raw     = parameters ?? throw new ArgumentNullException(nameof(parameters)),
            Options = options
        };

        var result = await ValidateClient(request, verifiedClientValidationResult).BindT(_ => ValidateScopeAsync(request));
        if (result.IsLeft)
            return result;

        logger.LogDebug("{ClientId} device authorization request validation success", request.ValidatedClient.Get().Client.ClientId);
        return Valid(request);
    }

    static DeviceAuthorizationRequestValidationResult Valid(ValidatedDeviceAuthorizationRequest request) => new(request);

    static DeviceAuthorizationRequestValidationError Invalid(ValidatedDeviceAuthorizationRequest request,
                                                             string error = OidcConstants.AuthorizeErrors.InvalidRequest,
                                                             string? description = null) =>
        new(request, error, description);

    void LogError(string message, ValidatedDeviceAuthorizationRequest request)
    {
        var requestDetails = new DeviceAuthorizationRequestValidationLog(request);
        logger.LogError("{Message}\n{RequestDetails}", message, requestDetails);
    }

    void LogError(string message, string detail, ValidatedDeviceAuthorizationRequest request)
    {
        var requestDetails = new DeviceAuthorizationRequestValidationLog(request);
        logger.LogError("{Message}: {Detail}\n{RequestDetails}", message, detail, requestDetails);
    }

    Either<DeviceAuthorizationRequestValidationError, DeviceAuthorizationRequestValidationResult> ValidateClient(
        ValidatedDeviceAuthorizationRequest request, VerifiedClient verifiedClientValidationResult) {
        var client = verifiedClientValidationResult.Client;
        request.ValidatedClient = ValidatedClient.Create(client, verifiedClientValidationResult.Secret);

        if (client.ProtocolType != IdentityServerConstants.ProtocolTypes.OpenIdConnect) {
            LogError("Invalid protocol type for OIDC authorize endpoint", client.ProtocolType, request);
            return Invalid(request, OidcConstants.AuthorizeErrors.UnauthorizedClient, "Invalid protocol");
        }

        if (!client.AllowedGrantTypes.Contains(GrantType.DeviceFlow)) {
            LogError("Client not configured for device flow", GrantType.DeviceFlow, request);
            return Invalid(request, OidcConstants.AuthorizeErrors.UnauthorizedClient);
        }

        return Valid(request);
    }

    async Task<Either<DeviceAuthorizationRequestValidationError, DeviceAuthorizationRequestValidationResult>> ValidateScopeAsync(ValidatedDeviceAuthorizationRequest request)
    {
        // scope must be present
        var client = request.ValidatedClient.Get(c => c.Client);
        var scope = request.Raw.Get(OidcConstants.AuthorizeRequest.Scope);
        if (scope!.IsMissing())
        {
            logger.LogTrace("Client provided no scopes - checking allowed scopes list");

            if (!client.AllowedScopes.IsNullOrEmpty())
            {
                var clientAllowedScopes = new List<string>(client.AllowedScopes);
                if (client.AllowOfflineAccess)
                {
                    clientAllowedScopes.Add(IdentityServerConstants.StandardScopes.OfflineAccess);
                }
                scope = clientAllowedScopes.ToSpaceSeparatedString();
                logger.LogTrace("Defaulting to: {Scopes}", scope);
            }
            else
            {
                LogError("No allowed scopes configured for client", request);
                return Invalid(request, OidcConstants.AuthorizeErrors.InvalidScope);
            }
        }
        Debug.Assert(scope != null);

        if (scope.Length > options.InputLengthRestrictions.Scope)
        {
            LogError("scopes too long.", request);
            return Invalid(request, description: "Invalid scope");
        }

        request.RequestedScopes = scope.FromSpaceSeparatedString().Distinct().ToArray();

        if (request.RequestedScopes.Contains(IdentityServerConstants.StandardScopes.OpenId)) request.IsOpenIdRequest = true;

        // check if scopes are valid/supported
        var validatedResources = await resourceValidator.ValidateScopesWithClient(new(client, request.RequestedScopes));

        if (!validatedResources.Succeeded)
            return validatedResources.InvalidScopes.Any()
                       ? Invalid(request, OidcConstants.AuthorizeErrors.InvalidScope)
                       : Invalid(request, OidcConstants.AuthorizeErrors.UnauthorizedClient, "Invalid scope");

        if (validatedResources.Resources.IdentityResources.Any() && !request.IsOpenIdRequest)
        {
            LogError("Identity related scope requests, but no openid scope", request);
            return Invalid(request, OidcConstants.AuthorizeErrors.InvalidScope);
        }

        request.ValidatedResources = validatedResources;

        return Valid(request);
    }
}