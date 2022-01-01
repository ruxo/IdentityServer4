// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Models;
using IdentityServer4.Extensions;
using IdentityServer4.Validation;
using Microsoft.Extensions.Logging;
using IdentityServer4.Stores;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services;

class OidcReturnUrlParser : IReturnUrlParser
{
    readonly IAuthorizeRequestValidator _validator;
    readonly IUserSession _userSession;
    readonly ILogger _logger;
    readonly IAuthorizationParametersMessageStore? _authorizationParametersMessageStore;

    public OidcReturnUrlParser(
        IAuthorizeRequestValidator           validator,
        IUserSession                         userSession,
        ILogger<OidcReturnUrlParser>         logger,
        IAuthorizationParametersMessageStore? authorizationParametersMessageStore = null)
    {
        _validator                           = validator;
        _userSession                         = userSession;
        _logger                              = logger;
        _authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public async Task<Option<AuthorizationRequest>> ParseAsync(string returnUrl)
    {
        if (IsValidReturnUrl(returnUrl))
        {
            var parameters = returnUrl.ReadQueryStringAsNameValueCollection();
            if (_authorizationParametersMessageStore != null)
            {
                var messageStoreId = parameters[Constants.AuthorizationParamsStore.MessageStoreIdParameterName];
                var entry = await _authorizationParametersMessageStore.ReadAsync(messageStoreId!);
                parameters = entry.Data.ToApiParameters();
            }

            var user = await _userSession.GetUserAsync();
            var result = await _validator.ValidateAsync(parameters, user.Get());
            if (!result.IsError)
            {
                _logger.LogTrace("AuthorizationRequest being returned");
                return new AuthorizationRequest(result.ValidatedRequest);
            }
        }

        _logger.LogTrace("No AuthorizationRequest being returned");
        return None;
    }

    public bool IsValidReturnUrl(string returnUrl)
    {
        if (returnUrl.IsLocalUrl())
        {
            var index = returnUrl.IndexOf('?');
            if (index >= 0)
            {
                returnUrl = returnUrl.Substring(0, index);
            }

            if (returnUrl.EndsWith(Constants.ProtocolRoutePaths.Authorize,         StringComparison.Ordinal) ||
                returnUrl.EndsWith(Constants.ProtocolRoutePaths.AuthorizeCallback, StringComparison.Ordinal))
            {
                _logger.LogTrace("returnUrl is valid");
                return true;
            }
        }

        _logger.LogTrace("returnUrl is not valid");
        return false;
    }
}