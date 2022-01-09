// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Events.Infrastructure;
using IdentityServer4.Extensions;
using IdentityServer4.Validation;
using IdentityServer4.Validation.Models;
using static IdentityServer4.Constants;

namespace IdentityServer4.Events;

/// <summary>
/// Event for failed token issuance
/// </summary>
/// <seealso cref="Event" />
public static class TokenIssuedFailureEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIssuedFailureEvent"/> class.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="error">The error.</param>
    /// <param name="description">The description.</param>
    public static Event Create(ValidatedAuthorizeRequest? request, string error, string description) =>
        new(EventCategories.Token,
            "Token Issued Failure",
            EventTypes.Failure,
            EventIds.TokenIssuedFailure,
            new{
                ClientId = request?.ValidatedClient.GetOrDefault(c => c.ClientId),
                ClientName = request?.ValidatedClient.GetOrDefault(c => c.Client.ClientName),
                RedirectUri = request?.RedirectUri,
                Scopes = request?.RequestedScopes.ToSpaceSeparatedString(),
                GrantType = request?.GrantType,
                SubjectId = request?.Subject.GetOrDefault(s => s.Identity?.IsAuthenticated) == true ? request.Subject.Get().GetRequiredSubjectId() : null,
                Endpoint = EndpointNames.Authorize,
                Error = error,
                ErrorDescription = description
            });

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenIssuedFailureEvent"/> class.
    /// </summary>
    public static Event Create(IBasicDebugInfo e) =>
        new(EventCategories.Token,
            "Token Issued Failure",
            EventTypes.Failure,
            EventIds.TokenIssuedFailure,
            new{
                Endpoint = EndpointNames.Token,
                e.Error,
                ErrorDescription = e.ErrorDescription.GetOrDefault(),
                Data = e.DebugInfo.GetOrDefault()
            });
}