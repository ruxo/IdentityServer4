using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using IdentityModel;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Models.Contexts;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using IdentityServer4.Validation.Default;
using IdentityServer4.Validation.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using RZ.Foundation.Helpers;

namespace IdentityServer4.Services.Default;

/// <inheritdoc />
public sealed class AuthContextParser : IAuthContextParser
{
    readonly ILogger<AuthContextParser> logger;
    readonly IdentityServerOptions options;
    readonly IClientStore clientStore;
    readonly ICustomAuthorizeRequestValidator customValidator;
    readonly IScopeParser scopeParser;
    readonly IResourceValidator resourceValidator;
    readonly IJwtRequestUriHttpClient jwtRequestClient;
    readonly JwtRequestValidator jwtValidator;
    readonly IRedirectUriValidator uriValidator;

    /// <summary>
    /// ctor
    /// </summary>
    public AuthContextParser(ILogger<AuthContextParser> logger, IClientStore clientStore, ICustomAuthorizeRequestValidator customValidator, IdentityServerOptions options,
                             IJwtRequestUriHttpClient jwtRequestClient,
                             IScopeParser scopeParser,
                             IRedirectUriValidator uriValidator,
                             IResourceValidator resourceValidator, JwtRequestValidator jwtValidator) {
        this.logger = logger;
        this.options = options;
        this.clientStore = clientStore;
        this.customValidator = customValidator;
        this.scopeParser = scopeParser;
        this.resourceValidator = resourceValidator;
        this.jwtRequestClient = jwtRequestClient;
        this.jwtValidator = jwtValidator;
        this.uriValidator = uriValidator;
    }

    /// <inheritdoc />
    public async ValueTask<AuthContext> CreateContext(ImmutableDictionary<string, StringValues> parameters) {
        var stopwatch = Stopwatch.StartNew();
        var responseType = parameters.TryGetSingle(OidcConstants.AuthorizeRequest.ResponseType)
                                     .Map(s => ResponseType.Create(s.FromSpaceSeparatedString()))
                                     .GetOrThrow(() => throw new BadRequestException(OidcConstants.AuthorizeErrors.UnsupportedResponseType, "Missing response_type"));
        var grantType = responseType.GetGrantType();
        var responseMode = parameters.TryGetSingle(OidcConstants.AuthorizeRequest.ResponseMode)
                                     .Map(ValidateResponseMode(grantType))
                                     .IfNone(() => Constants.AllowedResponseModesForGrantType[grantType].First());

        var clientId = getAndValidateLength(OidcConstants.AuthorizeRequest.ClientId, options.InputLengthRestrictions.ClientId)
                      .GetOrThrow(() => new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid client_id"));
        var scopes = getAndValidateLength(OidcConstants.AuthorizeRequest.Scope, options.InputLengthRestrictions.Scope)
                    .Map(s => s.FromSpaceSeparatedString().ToImmutableHashSet())
                    .GetOrThrow(() => new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid scope"));

        var client = (await clientStore.FindEnabledClientByIdAsync(clientId))
           .GetOrThrow(() => {
                logger.LogError("Unknown client {ClientId} or not enabled", clientId);
                return new BadRequestException(OidcConstants.AuthorizeErrors.UnauthorizedClient, "Unknown client or client not enabled");
            });

        var acrValues = getAndValidateLength(OidcConstants.AuthorizeRequest.AcrValues, options.InputLengthRestrictions.AcrValues)
                       .Map(s => s.FromSpaceSeparatedString().Distinct().ToArray())
                       .IfNone(Array.Empty<string>());

        var redirectUri = await ValidateRedirectUri(parameters.TryGetSingle, client);

        var (parsedScopes, invalidScopes) = scopeParser.ParseScopeValues(scopes);
        if (invalidScopes.Any())
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, $"Invalid scope values: {invalidScopes.Map(i => i.Scope).Join(", ")}");
        var (resources, invalids) = await resourceValidator.ValidateScopesWithClient(client, parsedScopes);
        if (invalids.Any())
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidScope, $"Invalid scopes: {invalids.Map(i => i.Scope).Join(", ")}");

        var request = parameters.TryGetSingle(OidcConstants.AuthorizeRequest.Request);
        var requestUri = getAndValidateLength(OidcConstants.AuthorizeRequest.RequestUri, 512 /* from spec */);

        var jwtRequest = await AuthorizeRequestValidator.GetOidcRequest(options, jwtRequestClient, client, request, requestUri);
        var additionalParameters = await jwtRequest.MapT(jwt => AuthorizeRequestValidator.ValidateClaimsFromToken(jwtValidator, parameters, client, responseType, jwt))
                                                   .IfNone(Enumerable.Empty<(string, string)>());

        var context = new AuthContext(responseType,
                                      grantType,
                                      responseMode,
                                      clientId,
                                      scopes,
                                      parsedScopes,
                                      resources,
                                      client,
                                      ValidateAcrValues(client, acrValues),
                                      redirectUri,
                                      parameters.TryGetSingle(OidcConstants.AuthorizeRequest.MaxAge).Map(ValidateMaxAge),
                                      parameters.TryGetSingle(OidcConstants.AuthorizeRequest.State),
                                      ValidatePkceData(parameters.TryGetSingle, client),
                                      getAndValidateLength(OidcConstants.AuthorizeRequest.Nonce, options.InputLengthRestrictions.Nonce),
                                      getAndValidateLength(OidcConstants.AuthorizeRequest.LoginHint, options.InputLengthRestrictions.LoginHint),
                                      parameters.TryGetSingle(OidcConstants.AuthorizeRequest.Prompt).Get(ValidatePromptMode),
                                      getAndValidateLength(OidcConstants.AuthorizeRequest.UiLocales, options.InputLengthRestrictions.UiLocale),
                                      parameters.TryGetSingle(OidcConstants.AuthorizeRequest.Display).Where(Constants.SupportedDisplayModes.Contains),
                                      request,
                                      requestUri,
                                      additionalParameters.ToArray());
        AuthorizeRequestValidator.ValidateContext(context);

        logger.LogInformation("Authorization request's context creation took {Time}ms", stopwatch.ElapsedMilliseconds);
        return await customValidator.ValidateAsync(context);

        Option<string> getAndValidateLength(string key, int maxLength) => parameters.TryGetSingle(key).Map(ValidateLength(key, maxLength));
    }

    string[] ValidateAcrValues(Client client, string[] acrValues) =>
        AuthContext.GetIdp(acrValues)
                   .Map(idp => {
                        if (!client.IdentityProviderRestrictions.Contains(idp)) {
                            logger.LogWarning("idp requested ({Idp}) is not in client restriction list", idp);
                            return acrValues.Where(v => v != idp).ToArray();
                        }
                        else
                            return acrValues;
                    })
                   .IfNone(acrValues);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static Func<string, string> ValidateLength(string name, int validLength) => AuthorizeRequestValidator.ValidateLength(name, validLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static Func<string, string> ValidateLength(string name, int minLength, int maxLength) => AuthorizeRequestValidator.ValidateLength(name, minLength, maxLength);

    Option<PkceData> ValidatePkceData(Func<string, Option<string>> tryGetSingle, Client client) {
        var codeChallenge = tryGetSingle(OidcConstants.AuthorizeRequest.CodeChallenge)
           .Map(ValidateLength("code_challenge",
                               options.InputLengthRestrictions.CodeChallengeMinLength,
                               options.InputLengthRestrictions.CodeChallengeMaxLength));
        if (codeChallenge.IsNone && client.RequirePkce)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "code challenge required");

        var codeChallengeMethod = tryGetSingle(OidcConstants.AuthorizeRequest.CodeChallengeMethod)
           .IfNone(OidcConstants.CodeChallengeMethods.Plain);
        if (!Constants.SupportedCodeChallengeMethods.Contains(codeChallengeMethod))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"Transform algorithm {codeChallengeMethod} not supported");
        if (codeChallengeMethod == OidcConstants.CodeChallengeMethods.Plain && !client.AllowPlainTextPkce)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "code_challenge_method of plain is not allowed");
        return new PkceData(codeChallenge.Get(), codeChallengeMethod);
    }

    async ValueTask<string> ValidateRedirectUri(Func<string, Option<string>> tryGetSingle, Client client) {
        var redirectUri = tryGetSingle(OidcConstants.AuthorizeRequest.RedirectUri)
                         .Map(ValidateLength("redirect_uri", options.InputLengthRestrictions.RedirectUri))
                         .GetOrThrow(() => new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "redirect_uri required"));
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid redirect_uri");
        if (client.ProtocolType != IdentityServerConstants.ProtocolTypes.OpenIdConnect)
            throw new BadRequestException(OidcConstants.AuthorizeErrors.UnauthorizedClient, "Invalid protocol");
        if (!await uriValidator.IsRedirectUriValidAsync(redirectUri, client))
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"Invalid redirect_uri {redirectUri}");
        return redirectUri;
    }

    Func<string, string> ValidateResponseMode(string grantType) => responseMode => {
        if (Constants.SupportedResponseModes.Contains(responseMode)) {
            if (Constants.AllowedResponseModesForGrantType[grantType].Contains(responseMode))
                return responseMode;
            logger.LogError("Invalid response_mode for response_type: {ResponseMode}", responseMode);
            throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid response_mode for response_type");
        }
        logger.LogError("Unsupported response_mode: {ResponseMode}", responseMode);
        throw new BadRequestException(OidcConstants.AuthorizeErrors.UnsupportedResponseType, "Invalid response_mode");
    };

    ImmutableHashSet<string> ValidatePromptMode(string prompt) {
        var prompts = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableHashSet();
        if (prompts.All(Constants.SupportedPromptModes.Contains)) {
            var noUiRendering = prompts.Contains(OidcConstants.PromptModes.None);
            if (prompts.Count > 1 && noUiRendering) {
                logger.LogError("prompt contains 'none' and other values. 'none' should be used by itself");
                throw new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, "Invalid prompt");
            }
            return prompts;
        }
        logger.LogDebug("Unsupported prompt mode - ignored: {Prompt}", prompt);
        return ImmutableHashSet<string>.Empty;
    }

    static int ValidateMaxAge(string s) =>
        TryConvert.ToInt32(s)
                  .Where(i => i >= 0).GetOrThrow(() => new BadRequestException(OidcConstants.AuthorizeErrors.InvalidRequest, $"Invalid max_age: {s}"));
}