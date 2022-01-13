// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace IdentityServer4.Extensions;

static class StringExtensions
{
    [DebuggerStepThrough]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string ToSpaceSeparatedString(this IEnumerable<string> list) => list.Join(' ');

    [DebuggerStepThrough]
    public static IEnumerable<string> FromSpaceSeparatedString(this string? input) => (input ?? string.Empty).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

    [DebuggerStepThrough]
    public static IEnumerable<string> ParseScopesString(this string? scopes) => scopes.FromSpaceSeparatedString().OrderBy(self => self).Distinct();

    [DebuggerStepThrough]
    public static bool IsMissing(this string? value) => string.IsNullOrWhiteSpace(value);

    [DebuggerStepThrough]
    public static bool IsMissingOrTooLong(this string value, int maxLength) => string.IsNullOrWhiteSpace(value) || value.Length > maxLength;

    [DebuggerStepThrough]
    public static bool IsPresent(this string? value) => !string.IsNullOrWhiteSpace(value);

    [DebuggerStepThrough]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Option<string> AsPresent(this string? value) => Optional(value!);

    [DebuggerStepThrough]
    public static string EnsureLeadingSlash(this string url)
    {
        if (url != null && !url.StartsWith("/"))
        {
            return "/" + url;
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string EnsureTrailingSlash(this string url)
    {
        if (url != null && !url.EndsWith("/"))
        {
            return url + "/";
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string RemoveLeadingSlash(this string url) => url.StartsWith("/") ? url[1..] : url;

    [DebuggerStepThrough]
    public static string RemoveTrailingSlash(this string url)
    {
        if (url != null && url.EndsWith("/"))
        {
            url = url.Substring(0, url.Length - 1);
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string CleanUrlPath(this string url)
    {
        if (String.IsNullOrWhiteSpace(url)) url = "/";

        if (url != "/" && url.EndsWith("/"))
        {
            url = url.Substring(0, url.Length - 1);
        }

        return url;
    }

    [DebuggerStepThrough]
    public static bool IsLocalUrl(this string url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Allows "/" or "/foo" but not "//" or "/\".
        if (url[0] == '/')
        {
            // url is exactly "/"
            if (url.Length == 1)
            {
                return true;
            }

            // url doesn't start with "//" or "/\"
            if (url[1] != '/' && url[1] != '\\')
            {
                return true;
            }

            return false;
        }

        // Allows "~/" or "~/foo" but not "~//" or "~/\".
        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            // url is exactly "~/"
            if (url.Length == 2)
            {
                return true;
            }

            // url doesn't start with "~//" or "~/\"
            if (url[2] != '/' && url[2] != '\\')
            {
                return true;
            }

            return false;
        }

        return false;
    }

    [DebuggerStepThrough]
    public static string AddQueryString(this string url, string query)
    {
        if (!url.Contains("?"))
        {
            url += "?";
        }
        else if (!url.EndsWith("&"))
        {
            url += "&";
        }

        return url + query;
    }

    [DebuggerStepThrough]
    public static string AddQueryString(this string url, string name, string value)
    {
        return url.AddQueryString(name + "=" + UrlEncoder.Default.Encode(value));
    }

    [DebuggerStepThrough]
    public static string AddHashFragment(this string url, string query)
    {
        if (!url.Contains("#"))
        {
            url += "#";
        }

        return url + query;
    }

    [DebuggerStepThrough]
    public static ApiParameters ReadQueryStringAsApiParameters(this string url)
    {
        var idx = url.IndexOf('?');
        var queryString = idx >= 0? url[(idx + 1)..] : string.Empty;
        return QueryHelpers.ParseNullableQuery(queryString)!.ToImmutableDictionary();
    }

    public static string GetOrigin(this string url)
    {
        if (url != null)
        {
            Uri uri;
            try
            {
                uri = new Uri(url);
            }
            catch (Exception)
            {
                return null;
            }

            if (uri.Scheme == "http" || uri.Scheme == "https")
            {
                return $"{uri.Scheme}://{uri.Authority}";
            }
        }

        return null;
    }

    [Pure]
    public static string Obfuscate(this string value)
    {
        var last4Chars = "****";
        if (value.IsPresent() && value.Length > 4)
        {
            last4Chars = value.Substring(value.Length - 4);
        }

        return "****" + last4Chars;
    }
}