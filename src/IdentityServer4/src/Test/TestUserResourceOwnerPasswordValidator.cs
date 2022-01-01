// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Validation;
using System;
using IdentityServer4.Models;
using IdentityServer4.Validation.Contexts;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;

namespace IdentityServer4.Test;

/// <summary>
/// Resource owner password validator for test users
/// </summary>
/// <seealso cref="IdentityServer4.Validation.IResourceOwnerPasswordValidator" />
public class TestUserResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
{
    readonly TestUserStore users;
    readonly ISystemClock clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestUserResourceOwnerPasswordValidator"/> class.
    /// </summary>
    /// <param name="users">The users.</param>
    /// <param name="clock">The clock.</param>
    public TestUserResourceOwnerPasswordValidator(TestUserStore users, ISystemClock clock)
    {
        this.users = users;
        this.clock = clock;
    }

    /// <summary>
    /// Validates the resource owner password credential
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public Task<Either<GrantValidationError, GrantValidationResult>> ValidateAsync(ResourceOwnerPasswordValidationContext context) {
        var user = users.ValidateCredentials(context.UserName, context.Password)
                       ? users.FindByUsername(context.UserName)
                               .Map(u => new GrantValidationResult(u.SubjectId ?? throw new ArgumentException("Subject ID not set", nameof(u.SubjectId)),
                                                                   OidcConstants.AuthenticationMethods.Password,
                                                                   clock.UtcNow.UtcDateTime,
                                                                   u.Claims))
                       : None;
        return Task.FromResult(user.ToEither(() => GrantValidationError.Create(TokenRequestErrors.InvalidRequest)));
    }
}