// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityServer4.Extensions;

static class NameValueCollectionExtensions
{
    public static Option<string> TryGetSingle(this ApiParameters parameters, string key) => parameters.Get(key).Where(s => s.Count > 0).Map(s => s[0]);

    public static PersistableApiParameters ToFullDictionary(this ApiParameters source) =>
        source.ToImmutableDictionary(k => k.Key, v => v.Value.ToArray());

    public static ApiParameters ToApiParameters(this PersistableApiParameters source) =>
        source.ToImmutableDictionary(k => k.Key, v => new StringValues(v.Value));

    public static ApiParameters ToApiParameters(this IDictionary<string, string> data) =>
        data.ToImmutableDictionary(k => k.Key, v => new StringValues(v.Value));

    public static string ToQueryString(this ApiParameters collection) => QueryString.Create(collection).ToString();

    public static string ToFormPost(this ApiParameters collection)
    {
        var builder = new StringBuilder(128);
        const string InputFieldFormat = "<input type='hidden' name='{0}' value='{1}' />\n";

        foreach (var (name,values) in collection) {
            var validName = HtmlEncoder.Default.Encode(name);
            var value = HtmlEncoder.Default.Encode(values.ToString());
            builder.AppendFormat(InputFieldFormat, validName, value);
        }

        return builder.ToString();
    }

    public static Dictionary<string, string> ToDictionary(this Dictionary<string,string> collection)
    {
        return collection.ToScrubbedDictionary();
    }

    public static Dictionary<string, string> ToScrubbedDictionary(this Dictionary<string,string> collection, params string[] nameFilter)
    {
        var dict = new Dictionary<string, string>();

        if (collection == null || collection.Count == 0)
        {
            return dict;
        }

        foreach (string name in collection)
        {
            var value = collection.Get(name);
            if (value != null)
            {
                if (nameFilter.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    value = "***REDACTED***";
                }
                dict.Add(name, value);
            }
        }

        return dict;
    }
}