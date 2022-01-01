// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Models;

/// <summary>
/// Base class for data that needs to be written out as cookies.
/// </summary>
public sealed record Message<TModel>(TModel Data, long Created);

/// <summary>
/// Message Helper
/// </summary>
public static class Message
{
    /// <summary>
    /// Should only be used from unit tests
    /// </summary>
    /// <param name="data"></param>
    public static Message<TModel> Create<TModel>(TModel data) => new(data, DateTime.UtcNow.Ticks);

    /// <summary>
    /// Initializes a new instance of the <see cref="Message{TModel}"/> class.
    /// </summary>
    /// <param name="data">The data.</param>
    /// <param name="now">The current UTC date/time.</param>
    public static Message<TModel> Create<TModel>(TModel data, DateTime now) => new(data, now.Ticks);
}