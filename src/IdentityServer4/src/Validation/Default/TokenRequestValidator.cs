// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Contexts;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using ValidationResult = LanguageExt.Either<IdentityServer4.Validation.Models.ErrorWithCustomResponse,LanguageExt.Unit>;

namespace IdentityServer4.Validation.Default;

class TokenRequestValidator : ITokenRequestValidator
{
    readonly IdentityServerOptions options;
    readonly IAuthorizationCodeStore authorizationCodeStore;
    readonly ExtensionGrantValidator extensionGrantValidator;
    readonly ICustomTokenRequestValidator customRequestValidator;
    readonly IResourceValidator resourceValidator;
    readonly IResourceStore resourceStore;
    readonly IRefreshTokenService refreshTokenService;
    readonly IEventService events;
    readonly IResourceOwnerPasswordValidator resourceOwnerValidator;
    readonly IProfileService profile;
    readonly IDeviceCodeValidator deviceCodeValidator;
    readonly ISystemClock clock;
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestValidator" /> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="authorizationCodeStore">The authorization code store.</param>
    /// <param name="resourceOwnerValidator">The resource owner validator.</param>
    /// <param name="profile">The profile.</param>
    /// <param name="deviceCodeValidator">The device code validator.</param>
    /// <param name="extensionGrantValidator">The extension grant validator.</param>
    /// <param name="customRequestValidator">The custom request validator.</param>
    /// <param name="resourceValidator">The resource validator.</param>
    /// <param name="resourceStore">The resource store.</param>
    /// <param name="refreshTokenService"></param>
    /// <param name="events">The events.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="logger">The logger.</param>
    public TokenRequestValidator(IdentityServerOptions           options,
                                 IAuthorizationCodeStore         authorizationCodeStore,
                                 IResourceOwnerPasswordValidator resourceOwnerValidator,
                                 IProfileService                 profile,
                                 IDeviceCodeValidator            deviceCodeValidator,
                                 ExtensionGrantValidator         extensionGrantValidator,
                                 ICustomTokenRequestValidator    customRequestValidator,
                                 IResourceValidator              resourceValidator,
                                 IResourceStore                  resourceStore,
                                 IRefreshTokenService            refreshTokenService,
                                 IEventService                   events,
                                 ISystemClock                    clock,
                                 ILogger<TokenRequestValidator>  logger)
    {
        this.logger                  = logger;
        this.options                 = options;
        this.clock                   = clock;
        this.authorizationCodeStore  = authorizationCodeStore;
        this.resourceOwnerValidator  = resourceOwnerValidator;
        this.profile                 = profile;
        this.deviceCodeValidator     = deviceCodeValidator;
        this.extensionGrantValidator = extensionGrantValidator;
        this.customRequestValidator  = customRequestValidator;
        this.resourceValidator       = resourceValidator;
        this.resourceStore           = resourceStore;
        this.refreshTokenService     = refreshTokenService;
        this.events                  = events;
    }

    /// <summary>
    /// Validates the request.
    /// </summary>
    /// <param name="parameters">The parameters.</param>
    /// <param name="clientValidationResult">The client validation result.</param>
    /// <returns></returns>
    /// <exception cref="System.ArgumentNullException">
    /// parameters
    /// or
    /// client
    /// </exception>
    public async Task<ValidationResult> ValidateRequestAsync(Dictionary<string,string> parameters, ClientSecretValidationResult clientValidationResult)
    {
        logger.LogDebug("Start token request validation");

        if (clientValidationResult == null) throw new ArgumentNullException(nameof(clientValidationResult));

        var client = clientValidationResult.Client;

        // check client protocol type
        if (client.ProtocolType != IdentityServerConstants.ProtocolTypes.OpenIdConnect) {
            logger.LogError("Invalid protocol type for client {@Client}",
                            new{
                                clientId = client.ClientId,
                                expectedProtocolType = IdentityServerConstants.ProtocolTypes.OpenIdConnect,
                                actualProtocolType = client.ProtocolType
                            });

            return Invalid(OidcConstants.TokenErrors.InvalidClient);
        }

        // check grant type
        var gt = parameters.Get(OidcConstants.TokenRequest.GrantType);
        if (gt.IsNone)
        {
            logger.LogError("Grant type is missing");
            return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
        }
        var grantType = gt.Get();

        if (grantType.Length > options.InputLengthRestrictions.GrantType)
        {
            logger.LogError("Grant type is too long");
            return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
        }

        var validatedRequest = new ValidatedTokenRequest{
            Raw     = parameters ?? throw new ArgumentNullException(nameof(parameters)),
            Options = options,
            ValidatedClient =  ValidatedClient.Create(clientValidationResult.Client, clientValidationResult.Secret, clientValidationResult.Confirmation),
            GrantType = grantType
        };

        return await (grantType switch{
            OidcConstants.GrantTypes.AuthorizationCode => ValidateAuthorizationCodeRequestAsync(validatedRequest, parameters),
            OidcConstants.GrantTypes.ClientCredentials => ValidateClientCredentialsRequestAsync(validatedRequest, parameters),
            OidcConstants.GrantTypes.Password          => ValidateResourceOwnerCredentialRequestAsync(validatedRequest, parameters),
            OidcConstants.GrantTypes.RefreshToken      => ValidateRefreshTokenRequestAsync(validatedRequest, parameters),
            OidcConstants.GrantTypes.DeviceCode        => ValidateDeviceCodeRequestAsync(validatedRequest, parameters),
            _                                          => ValidateExtensionGrantRequestAsync(validatedRequest, parameters)
        }).BindAsync(_ => RunValidationAsync(validatedRequest));
    }

    async Task<ValidationResult> RunValidationAsync(ValidatedTokenRequest validatedRequest) {
        // run custom validation
        logger.LogTrace("Calling into custom request validator: {Type}", customRequestValidator.GetType().FullName);

        var validatedTokenResult = await customRequestValidator.ValidateAsync(validatedRequest);
        if (validatedTokenResult.IsLeft)
            LogError(validatedRequest, "Custom token request validator", new{ error = validatedTokenResult.GetLeft().Error });
        else
            LogSuccess(validatedRequest);
        return validatedTokenResult;
    }

    async Task<ValidationResult> ValidateAuthorizationCodeRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters)
    {
        logger.LogDebug("Start validation of authorization code token request");
        var client = validatedRequest.ValidatedClient.Get(c => c.Client);

        // check if client is authorized for grant type
        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode) && !client.AllowedGrantTypes.Contains(GrantType.Hybrid))
        {
            LogError(validatedRequest, "Client not authorized for code flow");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // validate authorization code
        var codeOpt = parameters.Get(OidcConstants.TokenRequest.Code);
        if (codeOpt.IsNone)
        {
            LogError(validatedRequest, "Authorization code is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }
        var code = codeOpt.Get();

        if (code.Length > options.InputLengthRestrictions.AuthorizationCode)
        {
            LogError(validatedRequest, "Authorization code is too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        validatedRequest.AuthorizationCodeHandle = code;

        var az = await authorizationCodeStore.GetAuthorizationCodeAsync(code);
        if (az.IsNone)
        {
            LogError(validatedRequest, "Invalid authorization code", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }
        var authZcode = az.Get();

        // validate client binding
        if (authZcode.ClientId != client.ClientId)
        {
            LogError(validatedRequest, "Client is trying to use a code from a different client", new { clientId = client.ClientId, codeClient = authZcode.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // remove code from store
        // todo: set to consumed in the future?
        await authorizationCodeStore.RemoveAuthorizationCodeAsync(code);

        if (authZcode.CreationTime.HasExceeded(authZcode.Lifetime, clock.UtcNow.UtcDateTime))
        {
            LogError(validatedRequest, "Authorization code expired", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // populate session id
        if (authZcode.SessionId.IsPresent()) validatedRequest.SessionId = authZcode.SessionId;

        // validate code expiration
        if (authZcode.CreationTime.HasExceeded(client.AuthorizationCodeLifetime, clock.UtcNow.UtcDateTime))
        {
            LogError(validatedRequest, "Authorization code is expired");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        validatedRequest.AuthorizationCode = authZcode;
        validatedRequest.Subject           = authZcode.Subject;

        // validate redirect_uri
        var redirectUriOpt = parameters.Get(OidcConstants.TokenRequest.RedirectUri);
        if (redirectUriOpt.IsNone)
        {
            LogError(validatedRequest, "Redirect URI is missing");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }
        var redirectUri = redirectUriOpt.Get();

        var authorizationCode = validatedRequest.AuthorizationCode.Get();
        if (!redirectUri.Equals(authorizationCode.RedirectUri, StringComparison.Ordinal))
        {
            LogError(validatedRequest, "Invalid redirect_uri", new { redirectUri, expectedRedirectUri = authorizationCode.RedirectUri });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // validate scopes are present
        if (!validatedRequest.AuthorizationCode.Get().RequestedScopes.Any())
        {
            LogError(validatedRequest, "Authorization code has no associated scopes");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }

        // validate PKCE parameters
        var codeVerifier = parameters.Get(OidcConstants.TokenRequest.CodeVerifier).Get();

        if (client.RequirePkce || authorizationCode.CodeChallenge.IsPresent())
        {
            logger.LogDebug("Client required a proof key for code exchange. Starting PKCE validation");

            var proofKeyResult = ValidateAuthorizationCodeWithProofKeyParameters(validatedRequest, codeVerifier, authorizationCode);
            if (proofKeyResult.IsLeft)
                return proofKeyResult;

            validatedRequest.CodeVerifier = codeVerifier;
        }
        else
        {
            if (codeVerifier.IsPresent())
            {
                LogError(validatedRequest, "Unexpected code_verifier: {codeVerifier}. This happens when the client is trying to use PKCE, but it is not enabled. Set RequirePkce to true.", codeVerifier);
                return Invalid(OidcConstants.TokenErrors.InvalidGrant);
            }
        }

        // make sure user is enabled
        var subject = authorizationCode.Subject.Get();
        var isActive = await profile.IsActiveAsync(subject, client);

        if (!isActive)
        {
            LogError(validatedRequest, "User has been disabled", new { subjectId = subject.GetSubjectId() });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        logger.LogDebug("Validation of authorization code token request success");

        return Valid();
    }

    async Task<ValidationResult> ValidateClientCredentialsRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters)
    {
        logger.LogDebug("Start client credentials token request validation");

        var client = validatedRequest.ValidatedClient.Get().Client;

        // check if client is authorized for grant type
        if (!client.AllowedGrantTypes.Contains(GrantType.ClientCredentials))
        {
            LogError(validatedRequest, "Client not authorized for client credentials flow, check the AllowedGrantTypes setting", new { clientId = client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // check if client is allowed to request scopes
        if (!await ValidateRequestedScopesAsync(validatedRequest, parameters, ignoreImplicitIdentityScopes: true, ignoreImplicitOfflineAccess: true))
            return Invalid(OidcConstants.TokenErrors.InvalidScope);

        if (validatedRequest.ValidatedResources.Resources.IdentityResources.Any())
        {
            LogError(validatedRequest, "Client cannot request OpenID scopes in client credentials flow", new { clientId = client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        if (validatedRequest.ValidatedResources.Resources.OfflineAccess)
        {
            LogError(validatedRequest, "Client cannot request a refresh token in client credentials flow", new { clientId = client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        logger.LogDebug("{ClientId} credentials token request validation success", client.ClientId);
        return Valid();
    }

    async Task<ValidationResult> ValidateResourceOwnerCredentialRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters)
    {
        logger.LogDebug("Start resource owner password token request validation");
        var client = validatedRequest.ValidatedClient.Get().Client;

        // check if client is authorized for grant type
        if (!client.AllowedGrantTypes.Contains(GrantType.ResourceOwnerPassword))
        {
            LogError(validatedRequest, "Client not authorized for resource owner flow, check the AllowedGrantTypes setting", new { client_id = client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // check if client is allowed to request scopes
        if (!await ValidateRequestedScopesAsync(validatedRequest, parameters))
            return Invalid(OidcConstants.TokenErrors.InvalidScope);

        // check resource owner credentials
        var un = parameters.Get(OidcConstants.TokenRequest.UserName);

        if (un.IsNone)
        {
            LogError(validatedRequest, "Username is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }
        var userName = un.Get();

        var password = parameters.Get(OidcConstants.TokenRequest.Password).Map(s => s.Trim()).IfNone(string.Empty);

        if (userName.Length > options.InputLengthRestrictions.UserName || password.Length > options.InputLengthRestrictions.Password)
        {
            LogError(validatedRequest, "Username or password too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        validatedRequest.UserName = userName;

        // authenticate user
        var resourceOwnerContext = new ResourceOwnerPasswordValidationContext(userName, password, validatedRequest);
        var result = await resourceOwnerValidator.ValidateAsync(resourceOwnerContext);

        if (result.IsLeft) {
            var err = result.GetLeft();
            if (err.Error == OidcConstants.TokenErrors.UnsupportedGrantType)
            {
                LogError(validatedRequest, "Resource owner password credential grant type not supported");
                await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "password grant type not supported", client.ClientId);

                return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType, customResponse: err.CustomResponse);
            }

            var errorDescription = err.ErrorDescription ?? "invalid_username_or_password";

            LogInformation(validatedRequest, "User authentication failed: ", errorDescription);
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, errorDescription, client.ClientId);

            return Invalid(err.Error, errorDescription, err.CustomResponse);
        }

        var resourceResult = result.GetRight();

        // make sure user is enabled
        var isActive = await profile.IsActiveAsync(resourceResult.Subject, client);

        if (!isActive)
        {
            LogError(validatedRequest, "User has been disabled", new { subjectId = resourceResult.Subject.GetRequiredSubjectId() });
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "user is inactive", client.ClientId);

            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        validatedRequest.UserName = userName;
        validatedRequest.Subject  = resourceResult.Subject;

        await RaiseSuccessfulResourceOwnerAuthenticationEventAsync(userName, resourceResult.Subject.GetRequiredSubjectId(), client.ClientId);
        logger.LogDebug("Resource owner password token request validation success");
        return Valid();
    }

    async Task<ValidationResult> ValidateRefreshTokenRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters)
    {
        logger.LogDebug("Start validation of refresh token request");

        var rth = parameters.Get(OidcConstants.TokenRequest.RefreshToken);
        if (rth.IsNone)
        {
            LogError(validatedRequest, "Refresh token is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }
        var refreshTokenHandle = rth.Get();

        if (refreshTokenHandle.Length > options.InputLengthRestrictions.RefreshToken)
        {
            LogError(validatedRequest, "Refresh token too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        var result = await refreshTokenService.ValidateRefreshTokenAsync(refreshTokenHandle, validatedRequest.ValidatedClient.Get().Client);

        if (result.IsLeft)
        {
            LogWarning(validatedRequest, "Refresh token validation failed. aborting");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }
        var refreshToken = result.GetRight();

        validatedRequest.RefreshToken       = refreshToken;
        validatedRequest.RefreshTokenHandle = refreshTokenHandle;
        validatedRequest.Subject            = refreshToken.Subject;

        logger.LogDebug("Validation of refresh token request success");
        // todo: more logging - similar to TokenValidator before

        return Valid();
    }

    async Task<ValidationResult> ValidateDeviceCodeRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters) {
        var client = validatedRequest.ValidatedClient.Get().Client;
        logger.LogDebug("Start validation of device code request");

        // check if client is authorized for grant type
        if (!client.AllowedGrantTypes.ToList().Contains(GrantType.DeviceFlow))
        {
            LogError(validatedRequest, "Client not authorized for device flow");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // validate device code parameter
        var deviceCode = parameters.Get(OidcConstants.TokenRequest.DeviceCode);
        if (deviceCode.IsNone)
        {
            LogError(validatedRequest, "Device code is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }

        if (deviceCode.Get().Length > options.InputLengthRestrictions.DeviceCode)
        {
            LogError(validatedRequest, "Device code too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // validate device code
        var result = await deviceCodeValidator.ValidateAsync(client, deviceCode.Get());

        return result.Map(_ => {
            logger.LogDebug("Validation of authorization code token request success");
            return Valid();
        });
    }

    async Task<ValidationResult> ValidateExtensionGrantRequestAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters)
    {
        var client = validatedRequest.ValidatedClient.Get().Client;
        logger.LogDebug("Start validation of custom grant token request");

        // check if client is allowed to use grant type
        if (!client.AllowedGrantTypes.Contains(validatedRequest.GrantType))
        {
            LogError(validatedRequest, "Client does not have the custom grant type in the allowed list, therefore requested grant is not allowed", new { clientId = client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
        }

        // check if a validator is registered for the grant type
        if (!extensionGrantValidator.GetAvailableGrantTypes().Contains(validatedRequest.GrantType, StringComparer.Ordinal))
        {
            LogError(validatedRequest, "No validator is registered for the grant type", new { grantType = validatedRequest.GrantType });
            return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
        }

        // check if client is allowed to request scopes
        if (!await ValidateRequestedScopesAsync(validatedRequest, parameters))
            return Invalid(OidcConstants.TokenErrors.InvalidScope);

        // validate custom grant type
        var result = await extensionGrantValidator.ValidateAsync(validatedRequest);

        if (result.IsLeft) {
            var err = result.GetLeft();
            LogError(validatedRequest, "Invalid extension grant", new{ error = err.Error });
            return Invalid(err.Error, err.ErrorDescription, err.CustomResponse);
        }
        var subject = result.GetRight().Subject;

        // make sure user is enabled
        var isActive = await profile.IsActiveAsync(subject, client);

        if (!isActive) {
            // todo: raise event?

            LogError(validatedRequest, "User has been disabled", new{ subjectId = subject.GetRequiredSubjectId() });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        validatedRequest.Subject = subject;

        logger.LogDebug("Validation of extension grant token request success");
        return Valid();
    }

    // todo: do we want to rework the semantics of these ignore params?
    // also seems like other workflows other than CC clients can omit scopes?
    async Task<bool> ValidateRequestedScopesAsync(ValidatedTokenRequest validatedRequest, Dictionary<string,string> parameters, bool ignoreImplicitIdentityScopes = false, bool ignoreImplicitOfflineAccess = false)
    {
        var client = validatedRequest.ValidatedClient.Get().Client;
        var scopes = parameters.Get(OidcConstants.TokenRequest.Scope);
        if (scopes.IsNone)
        {
            logger.LogTrace("Client provided no scopes - checking allowed scopes list");

            if (!client.AllowedScopes.IsNullOrEmpty())
            {
                // this finds all the scopes the client is allowed to access
                var clientAllowedScopes = new List<string>();
                if (ignoreImplicitIdentityScopes) {
                    var apiScopes = await resourceStore.FindApiScopesByNameAsync(client.AllowedScopes);
                    clientAllowedScopes.AddRange(apiScopes.Select(x => x.Name));
                }
                else {
                    var resources = await resourceStore.FindResourcesByScopeAsync(client.AllowedScopes);
                    clientAllowedScopes.AddRange(resources.ToScopeNames().Where(x => client.AllowedScopes.Contains(x)));
                }

                if (!ignoreImplicitOfflineAccess && client.AllowOfflineAccess)
                    clientAllowedScopes.Add(IdentityServerConstants.StandardScopes.OfflineAccess);

                scopes = clientAllowedScopes.Distinct().ToSpaceSeparatedString();
                logger.LogTrace("Defaulting to: {Scopes}", scopes.Get());
            }
            else
            {
                LogError(validatedRequest, "No allowed scopes configured for client", new { clientId = client.ClientId });
                return false;
            }
        }

        if (scopes.Get().Length > options.InputLengthRestrictions.Scope)
        {
            LogError(validatedRequest, "Scope parameter exceeds max allowed length");
            return false;
        }

        var requestedScopes = scopes.Get().ParseScopesString().ToArray();

        if (requestedScopes.Length == 0)
        {
            LogError(validatedRequest, "No scopes found in request");
            return false;
        }

        var resourceValidationResult = await resourceValidator.ValidateScopesWithClient(new(client, requestedScopes));

        if (!resourceValidationResult.Succeeded) {
            LogError(validatedRequest, resourceValidationResult.InvalidScopes.Any() ? "Invalid scopes requested" : "Invalid scopes for client requested");

            return false;
        }

        validatedRequest.RequestedScopes    = requestedScopes;
        validatedRequest.ValidatedResources = resourceValidationResult;

        return true;
    }

    ValidationResult ValidateAuthorizationCodeWithProofKeyParameters(ValidatedTokenRequest validatedRequest, string codeVerifier, AuthorizationCode authZcode)
    {
        if (authZcode.CodeChallenge.IsMissing() || authZcode.CodeChallengeMethod.IsMissing())
        {
            LogError(validatedRequest, "Client is missing code challenge or code challenge method", new { clientId = validatedRequest.ValidatedClient.Get().Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (codeVerifier.IsMissing())
        {
            LogError(validatedRequest, "Missing code_verifier");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (codeVerifier.Length < options.InputLengthRestrictions.CodeVerifierMinLength ||
            codeVerifier.Length > options.InputLengthRestrictions.CodeVerifierMaxLength)
        {
            LogError(validatedRequest, "code_verifier is too short or too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (Constants.SupportedCodeChallengeMethods.Contains(authZcode.CodeChallengeMethod) == false)
        {
            LogError(validatedRequest, "Unsupported code challenge method", new { codeChallengeMethod = authZcode.CodeChallengeMethod });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (ValidateCodeVerifierAgainstCodeChallenge(codeVerifier, authZcode.CodeChallenge, authZcode.CodeChallengeMethod) == false)
        {
            LogError(validatedRequest, "Transformed code verifier does not match code challenge");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        return Valid();
    }

    static bool ValidateCodeVerifierAgainstCodeChallenge(string codeVerifier, string codeChallenge, string codeChallengeMethod)
    {
        if (codeChallengeMethod == OidcConstants.CodeChallengeMethods.Plain)
            return TimeConstantComparer.IsEqual(codeVerifier.Sha256(), codeChallenge);

        var codeVerifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hashedBytes = codeVerifierBytes.Sha256();
        var transformedCodeVerifier = Base64Url.Encode(hashedBytes);

        return TimeConstantComparer.IsEqual(transformedCodeVerifier.Sha256(), codeChallenge);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static Unit Valid() => Unit.Default;

    static ErrorWithCustomResponse Invalid(string error, string? errorDescription = null, Dictionary<string, object>? customResponse = null) =>
        new(error, errorDescription, customResponse ?? new());

    void LogError(ValidatedTokenRequest validatedRequest, string? message = null, object? values = null) =>
        LogWithRequestDetails(validatedRequest, LogLevel.Error, message, values);

    void LogWarning(ValidatedTokenRequest validatedRequest, string? message = null, object? values = null) =>
        LogWithRequestDetails(validatedRequest, LogLevel.Warning, message, values);

    void LogInformation(ValidatedTokenRequest validatedRequest, string? message = null, object? values = null) =>
        LogWithRequestDetails(validatedRequest, LogLevel.Information, message, values);

    void LogWithRequestDetails(ValidatedTokenRequest validatedRequest, LogLevel logLevel, string? message = null, object? values = null)
    {
        var sensitiveValuesFilter = options.Logging.TokenRequestSensitiveValuesFilter;
        var details = CreateLogDetail(validatedRequest, sensitiveValuesFilter);

        if (message.IsPresent())
            if (values == null)
                logger.Log(logLevel, "{Message}, {@Details}", message, details);
            else
                logger.Log(logLevel, "{Message} {@Values}, details: {@Details}", message, values, details);
        else
            logger.Log(logLevel, "{@Details}", details);
    }

    [Pure]
    static object CreateLogDetail(ValidatedTokenRequest request, string[] sensitiveValuesFilter) =>
        new{
            Raw = request.Raw.ToScrubbedDictionary(sensitiveValuesFilter),
            ClientId = request.ValidatedClient.GetOrDefault(c => c.Client.ClientId),
            ClientName = request.ValidatedClient.GetOrDefault(c => c.Client.ClientName),
            Scopes = request.RequestedScopes.ToSpaceSeparatedString(),
            GrantType = request.GrantType,
            AuthorizationCode = request.AuthorizationCodeHandle.Obfuscate(),
            RefreshToken = request.RefreshTokenHandle.Obfuscate(),
            UserName = request.UserName
        };

    void LogSuccess(ValidatedTokenRequest validatedRequest) => LogWithRequestDetails(validatedRequest, LogLevel.Information, "Token request validation success");

    Task RaiseSuccessfulResourceOwnerAuthenticationEventAsync(string userName, string subjectId, string clientId) =>
        events.RaiseAsync(UserLoginSuccessEvent.Create(userName, subjectId, null, interactive: false, clientId));

    Task RaiseFailedResourceOwnerAuthenticationEventAsync(string userName, string error, string clientId) =>
        events.RaiseAsync(UserLoginFailureEvent.Create(userName, error, interactive: false, clientId: clientId));
}