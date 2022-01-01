// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Configuration.DependencyInjection.Options;
using IdentityServer4.Models;

namespace IdentityServer4.Validation.Models;

/// <summary>
/// Base class for a validate authorize or token request
/// </summary>
// TODO: Must break down this global state bag in the future...
public abstract class ValidatedRequest
{
    /// <summary>
    /// Gets or sets the raw request data
    /// </summary>
    /// <value>
    /// The raw.
    /// </value>
    public Dictionary<string,string> Raw { get; set; } = new();

    /// <summary>
    /// Gets or sets the subject.
    /// </summary>
    /// <value>
    /// The subject.
    /// </value>
    public Option<ClaimsPrincipal> Subject { get; set; }

    /// <summary>
    /// Gets or sets the session identifier.
    /// </summary>
    /// <value>
    /// The session identifier.
    /// </value>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identity server options.
    /// </summary>
    /// <value>
    /// The options.
    /// </value>
    public IdentityServerOptions Options { get; set; } = new ();

    /// <summary>
    /// Gets or sets the validated resources for the request.
    /// </summary>
    /// <value>
    /// The validated resources.
    /// </value>
    public ResourceValidationResult ValidatedResources { get; set; } = new();

    /// <summary>
    /// Validated client information
    /// </summary>
    public Option<ValidatedClient> ValidatedClient { get; set; }
}

/// <summary>
/// Represents an existing validated client
/// </summary>
/// <param name="Client"></param>
/// <param name="Secret">the secret used to authenticate the client.</param>
/// <param name="Confirmation">the value of the confirmation method (will become the cnf claim). Must be a JSON object.</param>
/// <param name="ClientId">the client ID that should be used for the current request (this is useful for token exchange scenarios)</param>
/// <param name="AccessTokenLifetime">
/// The effective access token lifetime for the current request.
/// This value is initially read from the client configuration but can be modified in the request pipeline
/// </param>
/// <param name="AccessTokenType">
/// The effective access token type for the current request.
/// This value is initially read from the client configuration but can be modified in the request pipeline
/// </param>
/// <param name="ClientClaims">
/// The client claims for the current request.
/// This value is initially read from the client configuration but can be modified in the request pipeline
/// </param>
public sealed record ValidatedClient(Client          Client,          Option<ParsedSecret> Secret, string Confirmation, string ClientId, int AccessTokenLifetime,
                                     AccessTokenType AccessTokenType, ClaimCollection      ClientClaims)
{
    /// <summary>
    /// Sets the client and the appropriate request specific settings.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="secret">The client secret (optional).</param>
    /// <param name="confirmation">The confirmation.</param>
    /// <exception cref="ArgumentNullException">client</exception>
    public static ValidatedClient Create(Client client, ParsedSecret? secret = null, string confirmation = "") =>
        new(client,
            Optional(secret!),
            confirmation,
            client.ClientId,
            client.AccessTokenLifetime,
            client.AccessTokenType,
            new(client.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType))));
}