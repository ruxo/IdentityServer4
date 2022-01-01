// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Validation result for end session callback requests.
/// </summary>
/// <param name="FrontChannelLogoutUrls">the client front-channel logout urls.</param>
public sealed record EndSessionCallbackValidationResult(IEnumerable<string> FrontChannelLogoutUrls);