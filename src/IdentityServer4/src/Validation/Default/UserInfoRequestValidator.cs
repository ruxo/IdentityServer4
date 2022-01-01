// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Default userinfo request validator
/// </summary>
/// <seealso cref="IdentityServer4.Validation.IUserInfoRequestValidator" />
class UserInfoRequestValidator : IUserInfoRequestValidator
{
    readonly ITokenValidator tokenValidator;
    readonly IProfileService profile;
    readonly ILogger logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserInfoRequestValidator" /> class.
    /// </summary>
    /// <param name="tokenValidator">The token validator.</param>
    /// <param name="profile">The profile service</param>
    /// <param name="logger">The logger.</param>
    public UserInfoRequestValidator(
        ITokenValidator tokenValidator,
        IProfileService profile,
        ILogger<UserInfoRequestValidator> logger)
    {
        this.tokenValidator = tokenValidator;
        this.profile = profile;
        this.logger = logger;
    }

    /// <summary>
    /// Validates a userinfo request.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <returns></returns>
    /// <exception cref="System.NotImplementedException"></exception>
    public async Task<UserInfoRequestValidationResult> ValidateRequestAsync(string accessToken)
    {
        // the access token needs to be valid and have at least the openid scope
        var tokenResult = await tokenValidator.ValidateAccessTokenAsync( accessToken, IdentityServerConstants.StandardScopes.OpenId);

        if (tokenResult.IsError)
        {
            return new UserInfoRequestValidationResult
            {
                IsError = true,
                Error = tokenResult.Error
            };
        }

        // the token must have a one sub claim
        var subClaim = tokenResult.Claims.SingleOrDefault(c => c.Type == JwtClaimTypes.Subject);
        if (subClaim == null)
        {
            logger.LogError("Token contains no sub claim");

            return new UserInfoRequestValidationResult
            {
                IsError = true,
                Error = OidcConstants.ProtectedResourceErrors.InvalidToken
            };
        }

        // create subject from incoming access token
        var claims = tokenResult.Claims.Where(x => !Constants.Filters.ProtocolClaimsFilter.Contains(x.Type));
        var subject = Principal.Create("UserInfo", claims.ToArray());

        // make sure user is still active
        var isActive = await profile.IsActiveAsync(subject, tokenResult.Client, IdentityServerConstants.ProfileIsActiveCallers.UserInfoRequestValidation);

        if (!isActive)
        {
            logger.LogError("User is not active: {sub}", subject.GetSubjectId());

            return new UserInfoRequestValidationResult
            {
                IsError = true,
                Error = OidcConstants.ProtectedResourceErrors.InvalidToken
            };
        }

        return new UserInfoRequestValidationResult
        {
            IsError = false,
            TokenValidationResult = tokenResult,
            Subject = subject
        };
    }
}