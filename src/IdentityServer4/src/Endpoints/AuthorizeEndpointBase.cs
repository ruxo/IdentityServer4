// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Immutable;
using System.Diagnostics;
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
using IdentityServer4.Models.Contexts;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using ResponseDict = System.Collections.Immutable.ImmutableDictionary<string, string>;

// ReSharper disable TemplateIsNotCompileTimeConstantProblem

namespace IdentityServer4.Endpoints;

abstract class AuthorizeEndpointBase : IEndpointHandler
{
    readonly IConsentService consentService;
    readonly ISystemClock clock;
    readonly ITokenService tokenService;
    readonly ITokenCreationService tokenCreationService;
    readonly IAuthorizationParametersMessageStore? authorizationParametersMessageStore;

    readonly IEventService events;
    readonly IKeyMaterialService keyMaterialService;
    readonly IMessageStore<ErrorMessage> errorMessageStore;
    readonly IProfileService profileService;
    readonly IdentityServerOptions options;
    readonly IAuthorizationCodeStore authorizationCodeStore;
    readonly IAuthContextParser contextParser;
    readonly IClaimsService claimsService;
    readonly IUserSession userSession;

    protected AuthorizeEndpointBase(
        ILogger logger,
        IdentityServerOptions options,
        IAuthorizationCodeStore authorizationCodeStore,
        IAuthContextParser contextParser,
        IClaimsService claimsService,
        IConsentService consentService,
        IEventService events,
        IKeyMaterialService keyMaterialService,
        IMessageStore<ErrorMessage> errorMessageStore,
        IProfileService profileService,
        ISystemClock clock,
        ITokenService tokenService,
        ITokenCreationService tokenCreationService,
        IUserSession userSession,
        IAuthorizationParametersMessageStore? authorizationParametersMessageStore) {
        this.events = events;
        this.keyMaterialService = keyMaterialService;
        this.errorMessageStore = errorMessageStore;
        this.profileService = profileService;
        this.options = options;
        this.authorizationCodeStore = authorizationCodeStore;
        this.contextParser = contextParser;
        this.claimsService = claimsService;
        Logger = logger;
        this.consentService = consentService;
        this.clock = clock;
        this.tokenService = tokenService;
        this.tokenCreationService = tokenCreationService;
        this.authorizationParametersMessageStore = authorizationParametersMessageStore;
        this.userSession = userSession;
    }

    protected ILogger Logger { get; }

    public abstract Task<Either<ErrorInfo, Unit>> HandleRequest(HttpContext context);

    internal async Task<ApiRenderer> ProcessAuthorizeRequestAsync(ApiParameters parameters, UserSession session, Option<ConsentResponse> consent) {
        if (session.IsAuthenticated)
            Logger.LogDebug("User in authorize request: {SubjectId}", session.AuthenticatedUser.SubjectId);
        else
            Logger.LogDebug("No user present in authorize request");

        AuthContext data;
        try {
            data = await contextParser.CreateContext(parameters);
        }
        catch (BadRequestException e) {
            await LogAndRaiseError(TokenIssuedFailureEvent.Create(e));

            throw new InvalidOperationException("Unsupported response mode", e);
        }

        try {
            if (session.IsAuthenticated || !consent.Map(c => !c.Granted && c.Error.HasValue).GetOrDefault())
                return await Render(data, session, consent);

            // special case when anonymous user has issued an error prior to authenticating
            Logger.LogInformation("Error: User consent result: {Error}", consent.GetOrDefault(c => c.Error));

            return await RenderAuthorizationResponse(session, data, consent, forError: true);
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
                       ? await RenderAuthorizationResponse(session, data, consent, forError: true)
                       : RedirectToErrorPage(data, new(e.Error, e.ErrorDescription.GetOrDefault()));
        }
    }

    async Task LogAndRaiseError(Event errorEvent) {
        Logger.LogError("[{Error}] {ErrorDescription}", errorEvent.Name, errorEvent.AdditionalData);
        await events.RaiseAsync(errorEvent);
    }

    async Task<ApiRenderer> Render(AuthContext data, UserSession session, Option<ConsentResponse> consent) {
        // TODO check scope with requirement from the validator!
        var noUiRendering = data.PromptModes.Contains(OidcConstants.PromptModes.None);

        var loginFlow = !session.IsAuthenticated || await ShouldLogin(data.PromptModes, session.AuthenticatedUser, data.Client, data.AcrValues, data.MaxAge);
        if (loginFlow)
        {
            if (noUiRendering)
                // prompt=none means do not show the UI
                throw AuthError(OidcConstants.AuthorizeErrors.LoginRequired, "Login is required but prompt mode is none!");
            return RenderLoginPage((data with { PromptModes = ImmutableHashSet<string>.Empty }).ToApiParameters());
        }

        var consentRequired = await consentService.RequiresConsentAsync(session.AuthenticatedUser.SubjectId, data.Client, data.ParsedScopes);
        if (!consentRequired) return await RenderAuthorizationResponse(session, data, consent);

        if (noUiRendering || !data.PromptModes.Contains(OidcConstants.PromptModes.Consent))
            throw AuthError(OidcConstants.AuthorizeErrors.ConsentRequired, "Error: prompt is none or not consent when consent is required");

        return consent.IsSome
                   ? await RenderConsentPage(consent.Get(), session, data, data.Resources, data.ParsedScopes)
                   : RenderNewConsent(data.ToApiParameters());
    }

    async Task<bool> ShouldLogin(IReadOnlySet<string> promptModes, AuthenticatedUser user, Client client, IEnumerable<string> acrValues, Option<int> maxAge) =>
        (promptModes.Contains(OidcConstants.PromptModes.Login) || promptModes.Contains(OidcConstants.PromptModes.SelectAccount))
     || !await profileService.IsActiveAsync(user.Subject, client)
     || GetIdp(acrValues).GetOrDefault(s => s != user.IdentityProvider)
     || maxAge.GetOrDefault(ma => clock.UtcNow > user.AuthenticationTime.AddSeconds(ma))
     || (!client.EnableLocalLogin && user.IdentityProvider == IdentityServerConstants.LocalIdentityProvider)
     || (client.IdentityProviderRestrictions.Any() && !client.IdentityProviderRestrictions.Contains(user.IdentityProvider))
     || client.UserSsoLifetime.GetOrDefault(lifetime => CheckSsoTimeout(clock.UtcNow, lifetime, user.AuthenticationTimeEpoch));

    static bool CheckSsoTimeout(DateTimeOffset now, int userSsoLifetime, long authenticationTimeEpoch) => now.ToUnixTimeSeconds() - authenticationTimeEpoch > userSsoLifetime;

    static Option<string> GetIdp(IEnumerable<string> acrValues) =>
        acrValues.TryFirst(s => s.StartsWith(Constants.KnownAcrValues.HomeRealm))
                 .Map(s => s[Constants.KnownAcrValues.HomeRealm.Length..]);

    #region Renderer

    ApiRenderer RenderRedirect(ApiParameters parameters, string returnUrlParameter, string targetUrl) => async context => {
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

    ApiRenderer RenderLoginPage(ApiParameters parameters) =>
        RenderRedirect(parameters, options.UserInteraction.LoginReturnUrlParameter, options.UserInteraction.LoginUrl);

    ApiRenderer RenderNewConsent(ImmutableDictionary<string, StringValues> parameters) =>
        RenderRedirect(parameters, options.UserInteraction.ConsentReturnUrlParameter, options.UserInteraction.ConsentUrl);

    async Task<ApiRenderer> RenderConsentPage(ConsentResponse consent, UserSession session, AuthContext data, IEnumerable<Resource> resources, ParsedScopeValue[] parsedScopes) {
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
            await consentService.UpdateConsentAsync(session.AuthenticatedUser.SubjectId, data.Client, rememberScopes);
        }
        return await RenderAuthorizationResponse(session, data, consent);
    }

    async ValueTask<ApiRenderer> RenderAuthorizationResponse(UserSession session, AuthContext data, Option<ConsentResponse> consent, bool forError = false) =>
        data.GrantType switch{
            GrantType.AuthorizationCode => RenderCodeFlowResponse(session, data, consent, forError),
            GrantType.Implicit          => RenderImplicitFlowResponse(session, data, authorizationCode: None, consent.Map(c => c.Description), forError),
            GrantType.Hybrid => RenderImplicitFlowResponse(session,
                                                           data,
                                                           await CreateAuthorizationCode(session, data, consent),
                                                           consent.Map(c => c.Description),
                                                           forError),
            _ => throw AuthError("unsupported_grant_type", $"Grant type {data.GrantType} not supported")
        };

    ApiRenderer RenderCodeFlowResponse(UserSession session, AuthContext data, Option<ConsentResponse> consent, bool forError) => async context => {
        Debug.Assert(session.IsAuthenticated);
        var id = await CreateAuthorizationCode(session, data, consent);

        var response = SessionStateToResponseDict(data.ClientId, data.RedirectUri, session.SessionId.Get())
                      .Append(("code", id))
                      .ToImmutableDictionary();

        await userSession.AddClientIdAsync(session, data.ClientId);

        return await ReturnResponse(forError, data.ResponseMode, data.RedirectUri, response)(context);
    };

    async Task<string> CreateAuthorizationCode(UserSession session, AuthContext data, Option<ConsentResponse> consent) {
        var sessionId = session.SessionId.Get();
        var code = new AuthorizationCode(clock.UtcNow.UtcDateTime,
                                         data.ClientId,
                                         data.Client.AuthorizationCodeLifetime,
                                         session.AuthenticatedUser.SubjectId,
                                         sessionId,
                                         consent.Map(c => c.Description),
                                         data.Pkce,
                                         data.Scopes.Contains(IdentityServerConstants.StandardScopes.OpenId),
                                         data.Scopes.ToArray(),
                                         data.RedirectUri,
                                         data.Nonce,
                                         await data.State.MapTV(s => GetStateHash(data.Client.AllowedIdentityTokenSigningAlgorithms, s)),
                                         consent.IsSome);
        return await authorizationCodeStore.StoreAuthorizationCodeAsync(code);
    }

    ApiRenderer RenderImplicitFlowResponse(UserSession session, AuthContext data, Option<string> authorizationCode, Option<string> description, bool forError) => async context => {
        Debug.Assert(session.IsAuthenticated);
        var sessionId = session.SessionId.Get();
        var accessToken = data.ResponseType.HasToken
                              ? Some(await tokenService.CreateAccessTokenAsync(session.AuthenticatedUser,
                                                                               sessionId,
                                                                               data.Client,
                                                                               data.Scopes,
                                                                               data.Resources,
                                                                               confirmation: None,
                                                                               description))
                              : None;
        var accessTokenValue = await accessToken.MapT(tokenService.CreateSecurityTokenAsync)
                                                .Map(token => (token, accessToken.Get().Lifetime));

        var jwt = data.ResponseType.HasIdToken ? Some(await GetJwt(session, data, accessTokenValue, authorizationCode, context)) : None;

        var response = AccessTokenToResponseDict(accessTokenValue)
                      .Concat(jwt.Map(v => ("id_token", v)))
                      .Concat(SessionStateToResponseDict(data.ClientId, data.RedirectUri, sessionId))
                      .Concat(authorizationCode.Map(ac => ("code", ac)))
                      .ToImmutableDictionary();

        return await ReturnResponse(forError, data.ResponseMode, data.RedirectUri, response)(context);
    };

    #region Parameter to Response value conversions

    static IEnumerable<(string Key, string Value)> AccessTokenToResponseDict(Option<(string Token, int Lifetime)> accessToken) {
        if (accessToken.IsNone) yield break;
        var (token, lifetime) = accessToken.Get();
        yield return ("access_token", token);
        yield return ("token_type", "Bearer");
        yield return ("expires_in", lifetime.ToString());
    }

    static IEnumerable<(string, string)> SessionStateToResponseDict(string clientId, string redirectUri, Option<string> sessionId) {
        if (sessionId.IsSome) yield return ("session_state", GenerateSessionStateValue(clientId, sessionId.Get(), redirectUri));
    }

    #endregion

    async Task<string> GetJwt(UserSession session, AuthContext data, Option<(string Token,int Lifetime)> authToken, Option<string> authorizationCode, HttpContext context) {
        // TODO: Dom, add a test for this. validate the at and c hashes are correct for the id_token when the client's alg doesn't match the server default.
        var allowedSignInAlgorithms = data.Client.AllowedIdentityTokenSigningAlgorithms;
        var algorithm = await keyMaterialService.GetSigningAlgorithm(allowedSignInAlgorithms);

        string createHash(string s) => CryptoHelper.CreateHashClaimValue(s, algorithm);
        Func<string, Claim> createHashClaim(string claimType) => s => new(claimType, createHash(s));

        var tokenHash = authToken.Map(i => i.Token).Map(createHashClaim(JwtClaimTypes.AccessTokenHash));
        var authCodeToken = authorizationCode.Map(createHashClaim(JwtClaimTypes.AuthorizationCodeHash));
        var stateHash = data.State.Map(createHashClaim(JwtClaimTypes.StateHash));
        var sessionId = session.SessionId.Map(s => new Claim(JwtClaimTypes.SessionId, s));

        var identityClaims = await claimsService.GetIdentityTokenClaimsAsync(session, data.Client, data.Resources, includeAllIdentityClaims: !data.ResponseType.AccessTokenNeeded);
        var claims = data.Nonce.Map(n => new Claim(JwtClaimTypes.Nonce, n))
                         .Append(new Claim(JwtClaimTypes.IssuedAt, clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64))
                         .Concat(tokenHash)
                         .Concat(authCodeToken)
                         .Concat(stateHash)
                         .Concat(sessionId)
                         .Concat(identityClaims)
                         .ToArray();
        var issuer = context.GetIdentityServerIssuerUri();
        return await tokenCreationService.CreateTokenAsync(OidcConstants.TokenTypes.IdentityToken,
                                                           allowedSignInAlgorithms,
                                                           issuer,
                                                           data.Client.IdentityTokenLifetime,
                                                           new[]{ data.Client.ClientId },
                                                           claims,
                                                           None);
    }

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

    ApiRenderer RedirectToErrorPage(AuthContext data, ErrorInfo error) => async context => {
        var response = ResponseDict.Empty
                                   .Add("error", error.Error)
                                   .Add("error_description", error.ErrorDescription ?? string.Empty);
        var errorModel = new ErrorMessage{
            RequestId = context.TraceIdentifier,
            Error = error.Error,
            ErrorDescription = error.ErrorDescription,
            UiLocales = data.UiLocales,
            DisplayMode = data.DisplayMode,
            ClientId = data.ClientId,

            // if we have a valid redirect uri, then include it to the error page
            RedirectUri = CreateRedirectUri(forError: true, data.ResponseMode, data.RedirectUri, response, context).ToString(),
            ResponseMode = data.ResponseMode
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

    async ValueTask<string> GetStateHash(IEnumerable<string> allowedAlgorithms, string state) {
        var algorithm = await keyMaterialService.GetSigningAlgorithm(allowedAlgorithms);
        return CryptoHelper.CreateHashClaimValue(state, algorithm);
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
}