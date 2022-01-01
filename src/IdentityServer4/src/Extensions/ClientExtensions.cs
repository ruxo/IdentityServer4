// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static LanguageExt.Prelude;

namespace IdentityServer4.Models;

/// <summary>
/// Extension methods for client.
/// </summary>
public static class ClientExtensions
{
    /// <summary>
    /// Returns true if the client is an implicit-only client.
    /// </summary>
    public static bool IsImplicitOnly(this Client client) =>
        client.AllowedGrantTypes.Length == 1 && client.AllowedGrantTypes[0] == GrantType.Implicit;

    /// <summary>
    /// Constructs a list of SecurityKey from a Secret collection
    /// </summary>
    /// <param name="secrets">The secrets</param>
    /// <returns></returns>
    public static Task<List<SecurityKey>> GetKeysAsync(this IEnumerable<Secret> secrets) {
        var secretList = Seq(secrets);

        var x509 = from s in secretList
                   where s.Type == IdentityServerConstants.SecretTypes.X509CertificateBase64
                   let cert = new X509Certificate2(Convert.FromBase64String(s.Value))
                   select (SecurityKey) new X509SecurityKey(cert);
        var jwk = from s in secretList
                  where s.Type == IdentityServerConstants.SecretTypes.JsonWebKey
                  select new Microsoft.IdentityModel.Tokens.JsonWebKey(s.Value);

        return Task.FromResult(x509.Concat(jwk).ToList());
    }
}