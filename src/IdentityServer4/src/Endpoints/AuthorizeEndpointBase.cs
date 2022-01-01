// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Events;
using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using RZ.Foundation.Helpers;
using ResponseDict = System.Collections.Immutable.ImmutableDictionary<string, string>;

// ReSharper disable TemplateIsNotCompileTimeConstantProblem

namespace IdentityServer4.Endpoints;

abstract class AuthorizeEndpointBase : IEndpointHandler
{
    readonly IClientStore clientStore;
    readonly IConsentService consentService;
    readonly IResourceValidator resourceValidator;
    readonly IScopeParser scopeParser;
    readonly ISystemClock clock;
    readonly IAuthorizationParametersMessageStore? authorizationParametersMessageStore;

    readonly IEventService events;
    readonly IKeyMaterialService keyMaterialService;
    readonly IMessageStore<ErrorMessage> errorMessageStore;
    readonly IProfileService profileService;
    readonly IRedirectUriValidator uriValidator;
    readonly IdentityServerOptions options;
    readonly IAuthorizationCodeStore authorizationCodeStore;

    protected AuthorizeEndpointBase(
        ILogger logger,
        IdentityServerOptions options,
        IAuthorizationCodeStore authorizationCodeStore,
        IClientStore clientStore,
        IConsentService consentService,
        IEventService events,
        IKeyMaterialService keyMaterialService,
        IMessageStore<ErrorMessage> errorMessageStore,
        IProfileService profileService,
        IRedirectUriValidator uriValidator,
        IResourceValidator resourceValidator,
        IScopeParser scopeParser,
        ISystemClock clock,
        IUserSession userSession,
        IAuthorizationParametersMessageStore? authorizationParametersMessageStore) {
        this.events = events;
        this.keyMaterialService = keyMaterialService;
        this.errorMessageStore = errorMessageStore;
        this.profileService = profileService;
        this.uriValidator = uriValidator;
        this.options = options;
        this.authorizationCodeStore = authorizationCodeStore;
        Logger = logger;
        this.clientStore = clientStore;
        this.consentService = consentService;
        this.resourceValidator = resourceValidator;
        this.scopeParser = scopeParser;
        this.clock = clock;
        this.authorizationParametersMessageStore = authorizationParametersMessageStore;
        UserSession = userSession;
    }

    protected ILogger Logger { get; }

    protected IUserSession UserSession { get; }

    public abstract Task<Unit> HandleRequest(HttpContext context);

    internal async Task<ApiRenderer> ProcessAuthorizeRequestAsync(ApiParameters parameters, Option<ClaimsPrincipal> user, Option<ConsentResponse> consent){
        if (user.IsSome)
            Logger.LogDebug("User in authorize request: {SubjectId}", user.Get(u => u.GetSubjectId()));
        else
            Logger.LogDebug("No user present in authorize request");

        AuthContext data;
        try {
            data = await CreateContext(parameters.TryGetSingle);
        }
        catch (BadRequestException e) {
            await LogAndRaiseError(TokenIssuedFailureEvent.Create(e));

            throw new InvalidOperationException("Unsupported response mode", e);
        }

        var subject = user.IfNone(() => new(new ClaimsIdentity()));
        try {
            if (subject.IsAuthenticated() || !consent.Map(c => !c.Granted && c.Error.HasValue).GetOrDefault())
                return await Render(parameters, data, subject, consent);

            // special case when anonymous user has issued an error prior to authenticating
            Logger.LogInformation("Error: User consent result: {Error}", consent.GetOrDefault(c => c.Error));

            return RenderAuthorizationResponse(subject, data, consent, forError: true);
        }
        catch (BadRequestException e) {
            await LogAndRaiseError(TokenIssuedFailureEvent.Create(e));

            // these are the conditions where we can send a response
            // back directly to the client, otherwise we're only showing the error UI
            var isSafeError = e.Error is OidcConstants.AuthorizeErrors.AccessDenied
                                  or OidcConstants.AuthorizeErrors.AccountSelectionRequired
                                  or OidcConstants.AuthorizeErrors.LoginRequired
                                  or OidcConstants.AuthorizeErrors.ConsentRequired
                                  or OidcConstants.AuthorizeErrors.InteractionRequired;
            return isSafeError
                       ? RenderAuthorizationResponse(subject, data, consent, forError: true)
                       : RedirectToErrorPage(parameters, data.ResponseMode, data.ClientId, data.RedirectUri, new(e.Error, e.ErrorDescription.GetOrDefault()));
        }
    }

    async Task LogAndRaiseError(Event errorEvent) {
        Logger.LogError("[{Error}] {ErrorDescription}", errorEvent.Name, errorEvent.AdditionalData);
        await events.RaiseAsync(errorEvent);
    }

    async Task<ApiRenderer> Render(ImmutableDictionary<string,StringValues> parameters, AuthContext data, ClaimsPrincipal subject, Option<ConsentResponse> consent) {
        Option<string> tryGetSingle(string key) => parameters.Get(key).Where(s => s.Count > 0).Map(s => s[0]);

        var promptModes = tryGetSingle(OidcConstants.AuthorizeRequest.Prompt).Get(ValidatePromptMode);
        var noUiRendering = promptModes.Contains(OidcConstants.PromptModes.None);

        var (parsedScopes, invalidScopes) = scopeParser.ParseScopeValues(data.Scopes);
        if (invalidScopes.Any())
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidScope, $"Invalid scope values: {invalidScopes.Map(i => i.Scope).Join(", ")}");
        var (resources, invalids) = await resourceValidator.ValidateScopesWithClient(data.Client, parsedScopes);
        if (invalids.Any())
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidScope, $"Invalid scopes: {invalids.Map(i => i.Scope).Join(", ")}");

        // TODO check scope with requirement from the validator!

        var loginFlow = await ShouldLogin(promptModes, subject, data.Client, data.AcrValues, data.MaxAge);
        if (loginFlow)
        {
            if (noUiRendering)
                // prompt=none means do not show the UI
                throw AuthError(OidcConstants.AuthorizeErrors.LoginRequired, "Login is required but prompt mode is none!");
            return RenderLoginPage(parameters.Remove(OidcConstants.AuthorizeRequest.Prompt));
        }

        var consentRequired = await consentService.RequiresConsentAsync(subject, data.Client, parsedScopes);
        if (consentRequired) {
            if (noUiRendering || !promptModes.Contains(OidcConstants.PromptModes.Consent))
                throw AuthError(OidcConstants.AuthorizeErrors.ConsentRequired, "Error: prompt is none or not consent when consent is required");
            if (consent.IsSome)
                return await RenderConsentPage(consent.Get(), subject, data, resources, parsedScopes);
            else
                return RenderNewConsent(parameters);
        }

        // var request = result.ValidatedRequest;
        // LogRequest(request);
        //
        // // determine user interaction
        // var interactionResult = await interactionGenerator.ProcessInteractionAsync(request, consent);
        // if (interactionResult.IsError)
        //     return await CreateErrorResultAsync("Interaction generator error", request, interactionResult.Error, interactionResult.ErrorDescription, false);
        // if (interactionResult.IsLogin)
        //     return new LoginPageResult(request);
        // if (interactionResult.IsConsent)
        //     return new ConsentPageResult(request);
        // if (interactionResult.IsRedirect)
        //     return new CustomRedirectResult(request, interactionResult.RedirectUrl);
        //
        // var response = await authorizeResponseGenerator.CreateResponseAsync(request);
        //
        // await RaiseResponseEventAsync(response);
        //
        // LogResponse(response);
        //
        // return new AuthorizeResult(response);
        return RenderAuthorizationResponse(subject, data, consent);
    }

    async Task<bool> ShouldLogin(IReadOnlySet<string> promptModes, ClaimsPrincipal subject, Client client, string[] acrValues, Option<int> maxAge) =>
        (promptModes.Contains(OidcConstants.PromptModes.Login) || promptModes.Contains(OidcConstants.PromptModes.SelectAccount))
     || (!subject.IsAuthenticated() || !await profileService.IsActiveAsync(subject, client, IdentityServerConstants.ProfileIsActiveCallers.AuthorizeEndpoint))
     || GetIdp(acrValues).GetOrDefault(s => s != subject.GetIdentityProvider())
     || maxAge.GetOrDefault(ma => clock.UtcNow > subject.GetAuthenticationTime().AddSeconds(ma))
     || (!client.EnableLocalLogin && subject.GetIdentityProvider() == IdentityServerConstants.LocalIdentityProvider)
     || (client.IdentityProviderRestrictions.Any() && !client.IdentityProviderRestrictions.Contains(subject.GetIdentityProvider()))
     || client.UserSsoLifetime.GetOrDefault(lifetime => CheckSsoTimeout(clock.UtcNow, lifetime, subject.GetAuthenticationTimeEpoch()));

    static bool CheckSsoTimeout(DateTimeOffset now, int userSsoLifetime, long authenticationTimeEpoch) => now.ToUnixTimeSeconds() - authenticationTimeEpoch > userSsoLifetime;

    static Option<string> GetIdp(IEnumerable<string> acrValues) =>
        acrValues.TryFirst(s => s.StartsWith(Constants.KnownAcrValues.HomeRealm))
                 .Map(s => s[Constants.KnownAcrValues.HomeRealm.Length..]);

    #region Validations

    async Task<AuthContext> CreateContext(Func<string, Option<string>> tryGetSingle) {
        var responseType = tryGetSingle(OidcConstants.AuthorizeRequest.ResponseType)
                                     .Map(ValidateResponseType)
                                     .GetOrThrow(() => throw AuthError(OidcConstants.AuthorizeErrors.UnsupportedResponseType, "Missing response_type"));
        var grantType = ValidateGrantType(Constants.ResponseTypeToGrantTypeMapping[responseType]);
        var responseMode = tryGetSingle(OidcConstants.AuthorizeRequest.ResponseMode)
                                     .Map(ValidateResponseMode(grantType))
                                     .IfNone(() => Constants.AllowedResponseModesForGrantType[grantType].First());

        var clientId = tryGetSingle(OidcConstants.AuthorizeRequest.ClientId)
                                 .Where(cid => !cid.IsMissingOrTooLong(options.InputLengthRestrictions.ClientId))
                                 .GetOrThrow(() => AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid client_id"));
        var scopes = tryGetSingle(OidcConstants.AuthorizeRequest.Scope)
                               .Map(ValidateLength("scope", options.InputLengthRestrictions.Scope))
                               .Map(s => s.FromSpaceSeparatedString().ToImmutableHashSet())
                               .GetOrThrow(() => AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid scope"));

        var client = (await clientStore.FindClientByIdAsync(clientId))
           .GetOrThrow(() => {
                Logger.LogError("Unknown client {ClientId} or not enabled", clientId);
                return AuthError(OidcConstants.AuthorizeErrors.UnauthorizedClient, "Unknown client or client not enabled");
            });

        var acrValues = tryGetSingle(OidcConstants.AuthorizeRequest.AcrValues)
                                  .Map(ValidateLength("acr_values", options.InputLengthRestrictions.AcrValues))
                                  .Map(s => s.FromSpaceSeparatedString().Distinct().ToArray())
                                  .IfNone(Array.Empty<string>());
        var maxAge = tryGetSingle(OidcConstants.AuthorizeRequest.MaxAge).Map(ValidateMaxAge);

        var state = tryGetSingle(OidcConstants.AuthorizeRequest.State);
        var pkce = ValidatePkceData(tryGetSingle, client);
        var redirectUri = await ValidateRedirectUri(tryGetSingle, client);
        var nonce = tryGetSingle(OidcConstants.AuthorizeRequest.Nonce).Map(ValidateLength("nonce", options.InputLengthRestrictions.Nonce));

        if (nonce.IsNone && grantType is GrantType.Implicit or GrantType.Hybrid && scopes.Contains(IdentityServerConstants.StandardScopes.OpenId))
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Nonce required for implicit and hybrid flow with openid scope");

        return new(grantType, responseMode, clientId, scopes, client, acrValues, redirectUri, maxAge, state, pkce, nonce);
    }

    Func<string, string> ValidateLength(string name, int validLength) => s => {
        if (s.Length > validLength)
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too long");
        return s;
    };

    Func<string, string> ValidateLength(string name, int minLength, int maxLength) => s => {
        if (s.Length < minLength)
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too short");
        if (s.Length > maxLength)
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"{name} too long");
        return s;
    };

    Option<PkceData> ValidatePkceData(Func<string, Option<string>> tryGetSingle, Client client) {
        var codeChallenge = tryGetSingle(OidcConstants.AuthorizeRequest.CodeChallenge)
           .Map(ValidateLength("code_challenge",
                               options.InputLengthRestrictions.CodeChallengeMinLength,
                               options.InputLengthRestrictions.CodeChallengeMaxLength));
        if (codeChallenge.IsNone && client.RequirePkce)
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "code challenge required");

        var codeChallengeMethod = tryGetSingle(OidcConstants.AuthorizeRequest.CodeChallengeMethod)
           .IfNone(OidcConstants.CodeChallengeMethods.Plain);
        if (!Constants.SupportedCodeChallengeMethods.Contains(codeChallengeMethod))
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"Transform algorithm {codeChallengeMethod} not supported");
        if (codeChallengeMethod == OidcConstants.CodeChallengeMethods.Plain && !client.AllowPlainTextPkce)
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "code_challenge_method of plain is not allowed");
        return new PkceData(codeChallenge.Get(), codeChallengeMethod);
    }

    async Task<string> ValidateRedirectUri(Func<string, Option<string>> tryGetSingle, Client client) {
        var redirectUri = tryGetSingle(OidcConstants.AuthorizeRequest.RedirectUri)
                         .Map(ValidateLength("redirect_uri", options.InputLengthRestrictions.RedirectUri))
                         .GetOrThrow(() => AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "redirect_uri required"));
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid redirect_uri");
        if (client.ProtocolType != IdentityServerConstants.ProtocolTypes.OpenIdConnect)
            throw AuthError(OidcConstants.AuthorizeErrors.UnauthorizedClient, "Invalid protocol");
        if (!await uriValidator.IsRedirectUriValidAsync(redirectUri, client))
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"Invalid redirect_uri {redirectUri}");
        return redirectUri;
    }

    string ValidateResponseType(string responseType) {
        // The responseType may come in in an unconventional order.
        // Use an IEqualityComparer that doesn't care about the order of multiple values.
        // Per https://tools.ietf.org/html/rfc6749#section-3.1.1 -
        // 'Extension response types MAY contain a space-delimited (%x20) list of
        // values, where the order of values does not matter (e.g., response
        // type "a b" is the same as "b a").'
        // http://openid.net/specs/oauth-v2-multiple-response-types-1_0-03.html#terminology -
        // 'If a response type contains one of more space characters (%20), it is compared
        // as a space-delimited list of values in which the order of values does not matter.'
        var comparer = new ResponseTypeEqualityComparer();
        if (!Constants.SupportedResponseTypes.Contains(responseType, comparer))
        {
            Logger.LogError("Response type not supported: {ResponseType}", responseType);
            throw AuthError(OidcConstants.AuthorizeErrors.UnsupportedResponseType, "Response type not supported");
        }

        // Even though the responseType may have come in in an unconventional order,
        // we still need the request's ResponseType property to be set to the
        // conventional, supported response type.
        return Constants.SupportedResponseTypes.First( supportedResponseType => comparer.Equals(supportedResponseType, responseType));
    }

    string ValidateGrantType(string grantType) {
        // check if flow is allowed at authorize endpoint
        if (!Constants.AllowedGrantTypesForAuthorizeEndpoint.Contains(grantType))
        {
            Logger.LogError("Invalid grant type {GrantType}", grantType);
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid response_type");
        }
        return grantType;
    }

    Func<string, string> ValidateResponseMode(string grantType) => responseMode => {
        if (Constants.SupportedResponseModes.Contains(responseMode)) {
            if (Constants.AllowedResponseModesForGrantType[grantType].Contains(responseMode))
                return responseMode;
            Logger.LogError("Invalid response_mode for response_type: {ResponseMode}", responseMode);
            throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid response_mode for response_type");
        }
        Logger.LogError("Unsupported response_mode: {ResponseMode}", responseMode);
        throw AuthError(OidcConstants.AuthorizeErrors.UnsupportedResponseType, "Invalid response_mode");
    };

    System.Collections.Generic.HashSet<string> ValidatePromptMode(string prompt) {
        var prompts = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        if (prompts.All(Constants.SupportedPromptModes.Contains)) {
            if (prompts.Count > 1 && prompts.Contains(OidcConstants.PromptModes.None)) {
                Logger.LogError("prompt contains 'none' and other values. 'none' should be used by itself");
                throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid prompt");
            }
            return prompts;
        }
        Logger.LogDebug("Unsupported prompt mode - ignored: " + prompt);
        return new ();
    }

    int ValidateMaxAge(string s) => TryConvert.ToInt32(s).Where(i => i >= 0).GetOrThrow(() => AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"Invalid max_age: {s}"));

    #endregion

    #region Renderer

    ApiRenderer RenderRedirect(ImmutableDictionary<string, StringValues> parameters, string returnUrlParameter, string targetUrl) => async context => {
        async Task<Dictionary<string, StringValues>> useStoreId() {
            var msg = Message.Create(parameters.ToFullDictionary());
            var id = await authorizationParametersMessageStore.WriteAsync(msg);
            return new(){ { Constants.AuthorizationParamsStore.MessageStoreIdParameterName, id } };
        }

        var path = context.GetIdentityServerBasePath().EnsureTrailingSlash() + Constants.ProtocolRoutePaths.AuthorizeCallback;
        var qs = authorizationParametersMessageStore != null ? await useStoreId() : new(parameters);

        // this converts the relative redirect path to an absolute one if we're redirecting to a different server
        var returnUrl = targetUrl.IsLocalUrl() ? path : context.GetIdentityServerHost().EnsureTrailingSlash() + path.RemoveLeadingSlash();

        qs.Add(returnUrlParameter, returnUrl + QueryString.Create(qs));
        context.Response.RedirectToAbsoluteUrl(returnUrl + QueryString.Create(qs));
        return Unit.Default;
    };

    ApiRenderer RenderLoginPage(ImmutableDictionary<string, StringValues> parameters) =>
        RenderRedirect(parameters, options.UserInteraction.LoginReturnUrlParameter, options.UserInteraction.LoginUrl);

    ApiRenderer RenderNewConsent(ImmutableDictionary<string, StringValues> parameters) =>
        RenderRedirect(parameters, options.UserInteraction.ConsentReturnUrlParameter, options.UserInteraction.ConsentUrl);

    async Task<ApiRenderer> RenderConsentPage(ConsentResponse consent, ClaimsPrincipal subject, AuthContext data, IEnumerable<Resource> resources, ParsedScopeValue[] parsedScopes) {
        if (!consent.Granted) {
            // no need to show consent screen again
            var error = consent.Error switch{
                AuthorizationError.AccountSelectionRequired => OidcConstants.AuthorizeErrors.AccountSelectionRequired,
                AuthorizationError.ConsentRequired          => OidcConstants.AuthorizeErrors.ConsentRequired,
                AuthorizationError.InteractionRequired      => OidcConstants.AuthorizeErrors.InteractionRequired,
                AuthorizationError.LoginRequired            => OidcConstants.AuthorizeErrors.LoginRequired,
                _                                           => OidcConstants.AuthorizeErrors.AccessDenied
            };
            throw AuthError(error, consent.ErrorDescription);
        }

        // double check that required scopes are in the list of consented scopes
        var resourceNames = Seq(from r in resources
                                let requiredIdentity = r is IdentityResource{ Required: true }
                                let requiredApiScope = r is ApiScope{ Required        : true }
                                where requiredIdentity || requiredApiScope
                                select r.Name);
        var requiredScopes = parsedScopes.Where(ps => resourceNames.Contains(ps.Name)).Select(ps => ps.Name).ToArray();
        var invalidScopes = requiredScopes.Except(consent.ScopesValuesConsented).ToArray();
        if (invalidScopes.Any())
            throw AuthError(OidcConstants.AuthorizeErrors.AccessDenied, $"Error: User denied consent to required scopes: {invalidScopes.Join(", ")}");
        if (data.Client.AllowRememberConsent) {
            var rememberScopes = consent.RememberConsent ? parsedScopes : Array.Empty<ParsedScopeValue>();
            await consentService.UpdateConsentAsync(subject, data.Client, rememberScopes);
        }
        return RenderAuthorizationResponse(subject, data, consent);
    }

    ApiRenderer RenderAuthorizationResponse(ClaimsPrincipal subject, AuthContext data, Option<ConsentResponse> consent, bool forError = false) {
        if (data.GrantType == OidcConstants.GrantTypes.AuthorizationCode)
            return RenderCodeFlowResponse(subject, data, consent, forError);
        throw AuthError("unsupported_grant_type", $"Grant type {data.GrantType} not supported");
    }

    ApiRenderer RenderCodeFlowResponse(ClaimsPrincipal subject, AuthContext data, Option<ConsentResponse> consent, bool forError) => async context => {
        var sessionId = subject.IsAuthenticated()
                            ? await UserSession.GetSessionIdAsync().IfNoneAsync(() => string.Empty)
                            : string.Empty;
        var code = new AuthorizationCode(clock.UtcNow.UtcDateTime,
                                         data.ClientId,
                                         data.Client.AuthorizationCodeLifetime,
                                         subject,
                                         sessionId,
                                         consent.Map(c => c.Description),
                                         data.Pkce,
                                         data.Scopes.Contains(IdentityServerConstants.StandardScopes.OpenId),
                                         data.Scopes.ToArray(),
                                         data.RedirectUri,
                                         data.Nonce,
                                         await data.State.MapT(s => GetStateHash(data.Client, s)),
                                         consent.IsSome);
        var id = await authorizationCodeStore.StoreAuthorizationCodeAsync(code);

        var response = new Dictionary<string, string>{
            { "code", id },
            { "session_state", GenerateSessionStateValue(data.ClientId, sessionId, data.RedirectUri) }
        }.ToImmutableDictionary();

        await UserSession.AddClientIdAsync(data.ClientId);

        return await ReturnResponse(forError, data.ResponseMode, data.RedirectUri, response)(context);
    };

    ApiRenderer ReturnResponse(bool forError, string responseMode, string redirectUri, ResponseDict response) => async context => {
        switch (responseMode) {
            case OidcConstants.ResponseModes.Query or OidcConstants.ResponseModes.Fragment: {
                var finalUri = CreateRedirectUri(forError, responseMode, redirectUri, response, context);
                context.Response.Redirect(finalUri.ToString());
                return Unit.Default;
            }
            case OidcConstants.ResponseModes.FormPost: {
                // What is this magic value???
                context.Response.AddScriptCspHeaders(options.Csp, "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=");

                if (!context.Response.Headers.ContainsKey("Referrer-Policy"))
                    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
                await context.Response.WriteHtmlAsync(GetFormPostHtml(response, redirectUri));
                return Unit.Default;
            }
            default:
                throw AuthError(OidcConstants.AuthorizeErrors.InvalidRequest, $"Unsupported response mode {responseMode}");
        }
    };

    const string FormPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>";

    static string GetFormPostHtml(ResponseDict response, string redirectUri) =>
        FormPostHtml.Replace("{uri}", HtmlEncoder.Default.Encode(redirectUri))
                    .Replace("{body}", response.ToApiParameters().ToFormPost());

    ApiRenderer RedirectToErrorPage(ImmutableDictionary<string, StringValues> parameters, string responseMode, string clientId, string redirectUri, ErrorInfo error) =>
        async context => {
            var response = ResponseDict.Empty
                                       .Add("error", error.Error)
                                       .Add("error_description", error.ErrorDescription ?? string.Empty);
            var errorModel = new ErrorMessage{
                RequestId = context.TraceIdentifier,
                Error = error.Error,
                ErrorDescription = error.ErrorDescription,
                UiLocales = parameters.TryGetSingle(OidcConstants.AuthorizeRequest.UiLocales).Map(ValidateLength("ui_locales", options.InputLengthRestrictions.UiLocale)),
                DisplayMode = parameters.TryGetSingle(OidcConstants.AuthorizeRequest.Display).Where(Constants.SupportedDisplayModes.Contains),
                ClientId = clientId,

                // if we have a valid redirect uri, then include it to the error page
                RedirectUri = CreateRedirectUri(forError: true, responseMode, redirectUri, response, context).ToString(),
                ResponseMode = responseMode
            };

            var message = Message.Create(errorModel, clock.UtcNow.UtcDateTime);
            var id = await errorMessageStore.WriteAsync(message);

            var url = options.UserInteraction.ErrorUrl.AddQueryString(options.UserInteraction.ErrorIdParameter, id);
            context.Response.RedirectToAbsoluteUrl(url);
            return Unit.Default;
        };

    #endregion

    static TiraxTech.Uri CreateRedirectUri(bool forError, string responseMode, string redirectUri, ResponseDict response, HttpContext context) {
        context.Response.SetNoCache();
        var baseUri = TiraxTech.Uri.From(redirectUri);
        var parameters = response.ToApiParameters();
        var uri = responseMode == OidcConstants.ResponseModes.Query
                      ? baseUri.UpdateQueries(parameters)
                      : baseUri.SetFragment(QueryString.Create(parameters).ToString()[1..]);
        // https://tools.ietf.org/html/draft-bradley-oauth-open-redirector-00
        return forError && uri.Fragment == null ? uri.SetFragment("_=_") : uri;
    }

    async Task<string> GetStateHash(Client client, string state) {
        var credential = await keyMaterialService.GetSigningCredentialsAsync(client.AllowedIdentityTokenSigningAlgorithms);
        if (credential.IsNone)
            throw new InvalidOperationException("No signing credential is configured.");
        return CryptoHelper.CreateHashClaimValue(state, credential.Get().Algorithm);
    }

    static string GenerateSessionStateValue(string clientId, string sessionId, string redirectUri) {
        var salt = CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex);

        var uri = new Uri(redirectUri);
        var origin = uri.Scheme + "://" + uri.Host + (!uri.IsDefaultPort? string.Empty : ":" + uri.Port);
        var bytes = Encoding.UTF8.GetBytes(clientId + origin + sessionId + salt);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(bytes);

        return $"{Base64Url.Encode(hash)}.{salt}";
    }

    static Exception AuthError(string error, string? description = null) => new BadRequestException(error, description);

    sealed record AuthContext(string GrantType, string ResponseMode, string ClientId, ImmutableHashSet<string> Scopes, Client Client, string[] AcrValues,
                              string RedirectUri, Option<int> MaxAge, Option<string> State, Option<PkceData> Pkce, Option<string> Nonce);
}