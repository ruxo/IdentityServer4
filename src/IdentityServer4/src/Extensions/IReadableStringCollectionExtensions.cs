// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Immutable;
using Microsoft.Extensions.Primitives;
using System.Diagnostics;

#pragma warning disable 1591

namespace IdentityServer4.Extensions;

// TODO Remove this!
public static class IReadableStringCollectionExtensions
{
    [DebuggerStepThrough]
    public static ImmutableDictionary<string, StringValues> ToNameValueDictionary() =>
        collection.ToImmutableDictionary();

    [DebuggerStepThrough]
    public static ImmutableDictionary<string,string> ToNameValueDictionary() =>
        collection.ToImmutableDictionary(k => k.Key, v => v.Value.ToString());
}