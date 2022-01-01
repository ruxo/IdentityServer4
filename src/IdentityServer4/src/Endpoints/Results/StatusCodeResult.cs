// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.Endpoints.Results;

/// <summary>
/// Result for a raw HTTP status code
/// </summary>
public static class StatusCodeResult
{
    /// <summary>
    /// return Status Code
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Unit ReturnStatusCode(this HttpContext context, HttpStatusCode statusCode) => context.ReturnStatusCode((int)statusCode);

    /// <summary>
    /// return int code
    /// </summary>
    public static Unit ReturnStatusCode(this HttpContext context, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        return Unit.Default;
    }
}