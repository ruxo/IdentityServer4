// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using IdentityServer4.Extensions;
using IdentityServer4.Models.Contexts;
using Microsoft.Extensions.Logging;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services;

class OidcReturnUrlParser : IReturnUrlParser
{
    readonly IAuthContextParser authParser;
    readonly ILogger logger;
    readonly IAuthorizationParametersMessageStore? authorizationParametersMessageStore;

    public OidcReturnUrlParser(
        IAuthContextParser authParser,
        ILogger<OidcReturnUrlParser> logger,
        IAuthorizationParametersMessageStore? authorizationParametersMessageStore = null) {
        this.authParser = authParser;
        this.logger = logger;
        this.authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public async Task<Either<Exception, AuthContext>> ParseAsync(string returnUrl)
    {
        if (IsValidReturnUrl(returnUrl))
        {
            var parameters = returnUrl.ReadQueryStringAsApiParameters();
            if (authorizationParametersMessageStore != null)
            {
                var messageStoreId = parameters[Constants.AuthorizationParamsStore.MessageStoreIdParameterName];
                var entry = await authorizationParametersMessageStore.ReadAsync(messageStoreId!);
                parameters = entry.Data.ToApiParameters();
            }

            try {
                return await authParser.CreateContext(parameters);
            }
            catch (Exception e) {
                return e;
            }
        }

        logger.LogTrace("Return URL's parameters is not valid");
        return new BadRequestException("Return URL's parameters is not valid");
    }

    public bool IsValidReturnUrl(string returnUrl)
    {
        var index = returnUrl.IndexOf('?');
        var path = index >= 0 ? returnUrl[..index] : returnUrl;
        return returnUrl.IsLocalUrl() && (path.EndsWith(Constants.ProtocolRoutePaths.Authorize, StringComparison.Ordinal) ||
                                          path.EndsWith(Constants.ProtocolRoutePaths.AuthorizeCallback, StringComparison.Ordinal));
    }
}