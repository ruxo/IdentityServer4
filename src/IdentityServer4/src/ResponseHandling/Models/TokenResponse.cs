// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


// ReSharper disable once CheckNamespace
namespace IdentityServer4.ResponseHandling;

/// <summary>
/// Models a token response
/// </summary>
/// <param name="Custom">Custom entries.</param>
public sealed record TokenResponse(string AccessToken, int AccessTokenLifetime, Dictionary<string, object> Custom, string Scope, Option<string> IdentityToken,
                                   Option<string> RefreshToken);