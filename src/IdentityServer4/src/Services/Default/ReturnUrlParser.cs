// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Linq;
using IdentityServer4.Models.Contexts;

namespace IdentityServer4.Services.Default;

/// <summary>
/// Parses a return URL using all registered URL parsers
/// </summary>
public sealed class ReturnUrlParser
{
    readonly IEnumerable<IReturnUrlParser> parsers;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReturnUrlParser"/> class.
    /// </summary>
    /// <param name="parsers">The parsers.</param>
    public ReturnUrlParser(IEnumerable<IReturnUrlParser> parsers)
    {
        this.parsers = parsers;
    }

    /// <summary>
    /// Parses the return URL.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns></returns>
    public async Task<Option<AuthContext>> ParseAsync(string returnUrl)
    {
        foreach (var parser in parsers)
        {
            var result = await parser.ParseAsync(returnUrl);
            if (result.IsRight)
                return result.GetRight();
        }
        return None;
    }

    /// <summary>
    /// Determines whether a return URL is valid.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>
    ///   <c>true</c> if the return URL is valid; otherwise, <c>false</c>.
    /// </returns>
    public bool IsValidReturnUrl(string returnUrl) => parsers.Any(parser => parser.IsValidReturnUrl(returnUrl));
}