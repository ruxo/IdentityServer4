// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityServer4.Validation;

#pragma warning disable 1591

namespace IdentityServer4.Extensions;

public static class ValidatedAuthorizeRequestExtensions
{
    public static Option<string> GetPrefixedAcrValue(this ValidatedAuthorizeRequest request, string prefix) =>
        request.AuthenticationContextReferenceClasses
               .TryFirst(x => x.StartsWith(prefix))
               .Map(v => v[prefix.Length..]);

    public static void RemovePrefixedAcrValue(this ValidatedAuthorizeRequest request, string prefix)
    {
        request.AuthenticationContextReferenceClasses.RemoveAll(acr => acr.StartsWith(prefix, StringComparison.Ordinal));
        var acr_values = request.AuthenticationContextReferenceClasses.ToSpaceSeparatedString();
        if (acr_values.IsPresent())
        {
            request.Raw[OidcConstants.AuthorizeRequest.AcrValues] = acr_values;
        }
        else
        {
            request.Raw.Remove(OidcConstants.AuthorizeRequest.AcrValues);
        }
    }

    public static string GetIdP(this ValidatedAuthorizeRequest request)
    {
        return request.GetPrefixedAcrValue(Constants.KnownAcrValues.HomeRealm);
    }

    public static void RemoveIdP(this ValidatedAuthorizeRequest request)
    {
        request.RemovePrefixedAcrValue(Constants.KnownAcrValues.HomeRealm);
    }

    public static string GetTenant(this ValidatedAuthorizeRequest request)
    {
        return request.GetPrefixedAcrValue(Constants.KnownAcrValues.Tenant);
    }

    public static IEnumerable<string> GetAcrValues(this ValidatedAuthorizeRequest request)
    {
        return request
              .AuthenticationContextReferenceClasses
              .Where(acr => !Constants.KnownAcrValues.All.Any(well_known => acr.StartsWith(well_known)))
              .Distinct()
              .ToArray();
    }

    public static void RemoveAcrValue(this ValidatedAuthorizeRequest request, string value)
    {
        request.AuthenticationContextReferenceClasses.RemoveAll(x => x.Equals(value, StringComparison.Ordinal));
        var acr_values = request.AuthenticationContextReferenceClasses.ToSpaceSeparatedString();
        if (acr_values.IsPresent())
        {
            request.Raw[OidcConstants.AuthorizeRequest.AcrValues] = acr_values;
        }
        else
        {
            request.Raw.Remove(OidcConstants.AuthorizeRequest.AcrValues);
        }
    }

    public static void AddAcrValue(this ValidatedAuthorizeRequest request, string value)
    {
        if (String.IsNullOrWhiteSpace(value)) throw new ArgumentNullException(nameof(value));

        request.AuthenticationContextReferenceClasses.Add(value);
        var acr_values = request.AuthenticationContextReferenceClasses.ToSpaceSeparatedString();
        request.Raw[OidcConstants.AuthorizeRequest.AcrValues] = acr_values;
    }

    public static string GenerateSessionStateValue(this ValidatedAuthorizeRequest request)
    {
        if (!request.IsOpenIdRequest) return null;

        if (request.SessionId == null) return null;

        if (request.ClientId.IsMissing()) return null;
        if (request.RedirectUri.IsMissing()) return null;

        var clientId = request.ClientId;
        var sessionId = request.SessionId;
        var salt = CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex);

        var uri = new Uri(request.RedirectUri);
        var origin = uri.Scheme + "://" + uri.Host;
        if (!uri.IsDefaultPort)
        {
            origin += ":" + uri.Port;
        }

        var bytes = Encoding.UTF8.GetBytes(clientId + origin + sessionId + salt);
        byte[] hash;

        using (var sha = SHA256.Create())
        {
            hash = sha.ComputeHash(bytes);
        }

        return Base64Url.Encode(hash) + "." + salt;
    }
}