// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;

namespace IdentityServer4.Configuration.DependencyInjection.Options;

/// <summary>
/// Options for configuring logging behavior
/// </summary>
public sealed record LoggingOptions(string[] TokenRequestSensitiveValuesFilter, string[] AuthorizeRequestSensitiveValuesFilter)
{
    /// <summary>
    /// Default logging options
    /// </summary>
    public static readonly LoggingOptions Default = new(new[]{
                                                            OidcConstants.TokenRequest.ClientSecret,
                                                            OidcConstants.TokenRequest.Password,
                                                            OidcConstants.TokenRequest.ClientAssertion,
                                                            OidcConstants.TokenRequest.RefreshToken,
                                                            OidcConstants.TokenRequest.DeviceCode
                                                        },
                                                        new[]{
                                                            OidcConstants.AuthorizeRequest.IdTokenHint
                                                        });
}