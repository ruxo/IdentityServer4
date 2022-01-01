// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Json;
using System.Text.Json.Serialization;

namespace IdentityServer4.Logging;

/// <summary>
/// Helper to JSON serialize object data for logging.
/// </summary>
static class LogSerializer
{
    static readonly JsonSerializerOptions Options = new(){
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented          = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Serializes the specified object.
    /// </summary>
    /// <param name="logObject">The object.</param>
    /// <returns></returns>
    public static string Serialize(object logObject) => JsonSerializer.Serialize(logObject, Options);
}