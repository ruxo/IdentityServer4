// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Extensions;
using IdentityServer4.Models;

namespace IdentityServer4.Stores.Default;

// internal just for testing
class QueryStringAuthorizationParametersMessageStore : IAuthorizationParametersMessageStore
{
    public Task<string> WriteAsync(Message<IDictionary<string, string[]>> message)
    {
        var queryString = message.Data.ToApiParameters().ToQueryString();
        return Task.FromResult(queryString);
    }

    public Task<Message<IDictionary<string, string[]>>> ReadAsync(string id)
    {
        var values = id.ReadQueryStringAsApiParameters();
        var msg = Message.Create(values.ToFullDictionary());
        return Task.FromResult(msg);
    }

    public Task DeleteAsync(string id)
    {
        return Task.CompletedTask;
    }
}