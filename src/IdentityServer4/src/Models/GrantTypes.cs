// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

// ReSharper disable UnusedMember.Global
#pragma warning disable 1591

namespace IdentityServer4.Models;

// ReSharper disable once UnusedType.Global
public class GrantTypes
{
    public static string[] Implicit => new[] { GrantType.Implicit };
    public static string[] ImplicitAndClientCredentials => new[]  { GrantType.Implicit, GrantType.ClientCredentials };
    public static string[] Code => new[] { GrantType.AuthorizationCode };
    public static string[] CodeAndClientCredentials => new[] { GrantType.AuthorizationCode, GrantType.ClientCredentials };
    public static string[] Hybrid => new[] { GrantType.Hybrid };
    public static string[] HybridAndClientCredentials => new[] { GrantType.Hybrid, GrantType.ClientCredentials };
    public static string[] ClientCredentials => new[] { GrantType.ClientCredentials };
    public static string[] ResourceOwnerPassword => new[] { GrantType.ResourceOwnerPassword };
    public static string[] ResourceOwnerPasswordAndClientCredentials => new[] { GrantType.ResourceOwnerPassword, GrantType.ClientCredentials };
    public static string[] DeviceFlow => new[] { GrantType.DeviceFlow };
}