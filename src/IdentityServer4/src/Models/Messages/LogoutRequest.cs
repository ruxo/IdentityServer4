// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Specialized;
using System.Linq;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Validation;

namespace IdentityServer4.Models.Messages;

/// <summary>
/// Models the validated singout context.
/// </summary>
/// <param name="SubjectId">The subject identifier for the user at logout time.</param>
/// <param name="SessionId">The session identifier for the user at logout time.</param>
/// <param name="PostLogoutRedirectUri">the post logout redirect URI.</param>
/// <param name="ClientIds">Ids of clients known to have an authentication session for user at end session time.</param>
public sealed record LogoutMessage(string ClientId, string SubjectId, string SessionId,
                                   Option<string> ClientName, Option<string> PostLogoutRedirectUri, IEnumerable<string> ClientIds,
                                   Dictionary<string, string[]> Parameters)
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutMessage"/> class.
    /// </summary>
    public LogoutMessage(string clientId, string subjectId, string sessionId)
        : this(clientId, subjectId, sessionId, None, None, Enumerable.Empty<string>(), new()) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutMessage"/> class.
    /// </summary>
    /// <param name="request">The request.</param>
    public static LogoutMessage FromRequest(ValidatedEndSessionRequest request)
    {
        if (request.Client.IsNone)
            throw new InvalidOperationException("Request is missing client information");

        var parameters = request.Raw.ToFullDictionary();

        // optimize params sent to logout page, since we'd like to send them in URL (not as cookie)
        parameters.Remove(OidcConstants.EndSessionRequest.IdTokenHint);
        parameters.Remove(OidcConstants.EndSessionRequest.PostLogoutRedirectUri);
        parameters.Remove(OidcConstants.EndSessionRequest.State);

        ClientId   = request.Client?.ClientId;
        ClientName = request.Client?.ClientName;
        SubjectId  = request.Subject?.GetSubjectId();
        SessionId  = request.SessionId;
        ClientIds  = request.ClientIds;

        if (request.PostLogOutUri != null) {
            PostLogoutRedirectUri = request.PostLogOutUri;
            if (request.State != null) {
                PostLogoutRedirectUri = PostLogoutRedirectUri.AddQueryString(OidcConstants.EndSessionRequest.State, request.State);
            }
        }
        return new(request.Client)
    }

    /// <summary>
    ///  Flag to indicate if the payload contains useful information or not to avoid serailization.
    /// </summary>
    internal bool ContainsPayload => ClientIds.Any();
}

/// <summary>
/// Models the request from a client to sign the user out.
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutRequest"/> class.
    /// </summary>
    /// <param name="iframeUrl">The iframe URL.</param>
    /// <param name="message">The message.</param>
    public LogoutRequest(string iframeUrl, LogoutMessage message)
    {
        if (message != null)
        {
            ClientId              = message.ClientId;
            ClientName            = message.ClientName;
            PostLogoutRedirectUri = message.PostLogoutRedirectUri;
            SubjectId             = message.SubjectId;
            SessionId             = message.SessionId;
            ClientIds             = message.ClientIds;
            Parameters            = message.Parameters.ToApiParameters();
        }

        SignOutIFrameUrl = iframeUrl;
    }

    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public string ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client name.
    /// </summary>
    public string ClientName { get; set; }

    /// <summary>
    /// Gets or sets the post logout redirect URI.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the subject identifier for the user at logout time.
    /// </summary>
    public string SubjectId { get; set; }

    /// <summary>
    /// Gets or sets the session identifier for the user at logout time.
    /// </summary>
    public string SessionId { get; set; }

    /// <summary>
    ///  Ids of clients known to have an authentication session for user at end session time
    /// </summary>
    public IEnumerable<string> ClientIds { get; set; }

    /// <summary>
    /// Gets the entire parameter collection.
    /// </summary>
    public Dictionary<string,string> Parameters { get; } = new Dictionary<string,string>();

    /// <summary>
    /// Gets or sets the sign out iframe URL.
    /// </summary>
    /// <value>
    /// The sign out iframe URL.
    /// </value>
    public string SignOutIFrameUrl { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user should be prompted for signout.
    /// </summary>
    /// <value>
    ///   <c>true</c> if the signout prompt should be shown; otherwise, <c>false</c>.
    /// </value>
    public bool ShowSignoutPrompt => ClientId.IsMissing();
}