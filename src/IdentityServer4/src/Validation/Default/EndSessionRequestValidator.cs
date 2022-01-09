// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Logging.Models;
using IdentityServer4.Models.Contexts;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validates requests to the end session endpoint.
/// </summary>
public sealed class EndSessionRequestValidator : IEndSessionRequestValidator
{
    /// <summary>
    /// The logger.
    /// </summary>
    readonly ILogger logger;

    /// <summary>
    ///  The IdentityServer options.
    /// </summary>
    readonly IdentityServerOptions options;

    /// <summary>
    /// The token validator.
    /// </summary>
    readonly ITokenValidator tokenValidator;

    /// <summary>
    /// The URI validator.
    /// </summary>
    readonly IRedirectUriValidator uriValidator;

    /// <summary>
    /// The user session service.
    /// </summary>
    readonly IUserSession userSession;

    /// <summary>
    /// The logout notification service.
    /// </summary>
    public ILogoutNotificationService LogoutNotificationService { get; }

    /// <summary>
    /// The end session message store.
    /// </summary>
    readonly IMessageStore<LogoutNotificationContext> endSessionMessageStore;

    /// <summary>
    /// Creates a new instance of the EndSessionRequestValidator.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="tokenValidator"></param>
    /// <param name="uriValidator"></param>
    /// <param name="userSession"></param>
    /// <param name="logoutNotificationService"></param>
    /// <param name="endSessionMessageStore"></param>
    /// <param name="logger"></param>
    public EndSessionRequestValidator(IdentityServerOptions                    options,
                                      ITokenValidator                          tokenValidator,
                                      IRedirectUriValidator                    uriValidator,
                                      IUserSession                             userSession,
                                      ILogoutNotificationService               logoutNotificationService,
                                      IMessageStore<LogoutNotificationContext> endSessionMessageStore,
                                      ILogger<EndSessionRequestValidator>      logger)
    {
        this.options                   = options;
        this.tokenValidator            = tokenValidator;
        this.uriValidator              = uriValidator;
        this.userSession               = userSession;
        LogoutNotificationService = logoutNotificationService;
        this.endSessionMessageStore    = endSessionMessageStore;
        this.logger                    = logger;
    }

    /// <inheritdoc />
    public async Task<Either<ErrorInfo, EndSessionValidationResult>> ValidateAsync(Dictionary<string,string> parameters, ClaimsPrincipal subject)
    {
        logger.LogDebug("Start end session request validation");

        var isAuthenticated = subject.IsAuthenticated();

        if (!isAuthenticated && options.Authentication.RequireAuthenticatedUserForSignOutMessage)
            return Invalid("User is anonymous. Ignoring end session parameters");

        var validatedRequest = new ValidatedEndSessionRequest
        {
            Raw = parameters
        };

        var idTokenHint = parameters.Get(OidcConstants.EndSessionRequest.IdTokenHint);
        if (idTokenHint.IsPresent())
        {
            // validate id_token - no need to validate token life time
            var tokenValidationResult = await tokenValidator.ValidateIdentityTokenAsync(idTokenHint, null, false);
            if (tokenValidationResult.IsError)
            {
                return Invalid("Error validating id token hint", validatedRequest);
            }

            validatedRequest.Client = tokenValidationResult.Client;

            // validate sub claim against currently logged on user
            var subClaim = tokenValidationResult.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
            if (subClaim != null && isAuthenticated)
            {
                if (subject.GetRequiredSubjectId() != subClaim.Value)
                {
                    return Invalid("Current user does not match identity token", validatedRequest);
                }

                validatedRequest.Subject   = subject;
                validatedRequest.SessionId = await userSession.GetSessionIdAsync();
                validatedRequest.ClientIds = await userSession.GetClientListAsync();
            }

            var redirectUri = parameters.Get(OidcConstants.EndSessionRequest.PostLogoutRedirectUri);
            if (redirectUri.IsPresent())
            {
                if (await uriValidator.IsPostLogoutRedirectUriValidAsync(redirectUri, validatedRequest.Client))
                {
                    validatedRequest.PostLogOutUri = redirectUri;
                }
                else
                {
                    logger.LogWarning("Invalid PostLogoutRedirectUri: {postLogoutRedirectUri}", redirectUri);
                }
            }

            if (validatedRequest.PostLogOutUri != null)
            {
                var state = parameters.Get(OidcConstants.EndSessionRequest.State);
                if (state.IsPresent())
                {
                    validatedRequest.State = state;
                }
            }
        }
        else
        {
            // no id_token to authenticate the client, but we do have a user and a user session
            validatedRequest.Subject   = subject;
            validatedRequest.SessionId = await userSession.GetSessionIdAsync();
            validatedRequest.ClientIds = await userSession.GetClientListAsync();
        }

        LogSuccess(validatedRequest);

        return new EndSessionValidationResult
        {
            ValidatedRequest = validatedRequest,
            IsError          = false
        };
    }

    ErrorInfo Invalid(string message) {
        logger.LogInformation("End session request validation failure: {Message}", message);
        return new(ErrorInfo.InvalidRequest, message);
    }
    ErrorInfo Invalid(string message, ValidatedEndSessionRequest request)
    {
        var log = new EndSessionRequestValidationLog(request);
        logger.LogInformation("End session request validation failure: {Message}\r\n{@Details}", message, log);
        return new(ErrorInfo.InvalidRequest, message);
    }

    /// <summary>
    /// Logs a success result.
    /// </summary>
    /// <param name="request"></param>
    void LogSuccess(ValidatedEndSessionRequest request)
    {
        var log = new EndSessionRequestValidationLog(request);
        logger.LogInformation("End session request validation success\r\n{@Details}", log);
    }

    /// <inheritdoc />
    public async Task<Either<ErrorInfo, EndSessionCallbackValidationResult>> ValidateCallbackAsync(Dictionary<string,string> parameters)
    {
        var endSessionId = parameters[Constants.UIConstants.DefaultRoutePathParams.EndSessionCallback]
                        ?? throw new ArgumentException($"Parameters missing {Constants.UIConstants.DefaultRoutePathParams.EndSessionCallback}", nameof(parameters));
        var endSessionMessage = await endSessionMessageStore.ReadAsync(endSessionId);
        var data = endSessionMessage.Get(m => m.Data);
        return data.ClientIds.Any()
                   ? new EndSessionCallbackValidationResult(await LogoutNotificationService.GetFrontChannelLogoutNotificationsUrlsAsync(data))
                   : new ErrorInfo(ErrorInfo.InvalidInternalData, "Failed to read end session callback message");
    }
}