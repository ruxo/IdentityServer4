// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.Services.Default;

/// <summary>
/// Default consent service
/// </summary>
public sealed class DefaultConsentService : IConsentService
{
    /// <summary>
    /// The user consent store
    /// </summary>
    readonly IUserConsentStore userConsentStore;

    /// <summary>
    ///  The clock
    /// </summary>
    readonly ISystemClock clock;

    /// <summary>
    /// The logger
    /// </summary>
    readonly ILogger<DefaultConsentService> logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultConsentService" /> class.
    /// </summary>
    /// <param name="clock">The clock.</param>
    /// <param name="userConsentStore">The user consent store.</param>
    /// <param name="logger">The logger.</param>
    /// <exception cref="System.ArgumentNullException">store</exception>
    public DefaultConsentService(ISystemClock clock, IUserConsentStore userConsentStore, ILogger<DefaultConsentService> logger)
    {
        this.clock = clock;
        this.userConsentStore = userConsentStore;
        this.logger = logger;
    }

    /// <summary>
    /// Checks if consent is required.
    /// </summary>
    /// <param name="subject">The user.</param>
    /// <param name="client">The client.</param>
    /// <param name="parsedScopes">The parsed scopes.</param>
    /// <returns>
    /// Boolean if consent is required.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">
    /// client
    /// or
    /// subject
    /// </exception>
    public async Task<bool> RequiresConsentAsync(ClaimsPrincipal subject, Client client, IEnumerable<ParsedScopeValue> parsedScopes) {
        var ps = Seq(parsedScopes);
        if (!client.RequireConsent)
        {
            logger.LogDebug("Client is configured to not require consent, no consent is required");
            return false;
        }

        if (!ps.Any())
        {
            logger.LogDebug("No scopes being requested, no consent is required");
            return false;
        }

        if (!client.AllowRememberConsent)
        {
            logger.LogDebug("Client is configured to not allow remembering consent, consent is required");
            return true;
        }

        if (ps.Any(x => x.Type == ParsedScopeType.Structure))
        {
            logger.LogDebug("Scopes contains parameterized values, consent is required");
            return true;
        }

        var scopes = ps.Select(x => x.Name);

        // we always require consent for offline access if
        // the client has not disabled RequireConsent
        if (scopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess))
        {
            logger.LogDebug("Scopes contains offline_access, consent is required");
            return true;
        }

        var cs = await userConsentStore.GetUserConsentAsync(subject.GetSubjectId(), client.ClientId);

        if (cs.IsNone)
        {
            logger.LogDebug("Found no prior consent from consent store, consent is required");
            return true;
        }
        var consent = cs.Get();

        if (consent.Expiration.HasExpired(clock.UtcNow.UtcDateTime))
        {
            logger.LogDebug("Consent found in consent store is expired, consent is required");
            await userConsentStore.RemoveUserConsentAsync(consent.SubjectId, consent.ClientId);
            return true;
        }

        if (consent.Scopes.Any())
        {
            var intersect = scopes.Intersect(consent.Scopes);
            var different = scopes.Count() != intersect.Count();

            // ReSharper disable once TemplateIsNotCompileTimeConstantProblem
            logger.LogDebug(different
                                ? "Consent found in consent store is different than current request, consent is required"
                                : "Consent found in consent store is same as current request, consent is not required");

            return different;
        }

        logger.LogDebug("Consent found in consent store has no scopes, consent is required");

        return true;
    }

    /// <summary>
    /// Updates the consent asynchronous.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="subject">The subject.</param>
    /// <param name="parsedScopes">The parsed scopes.</param>
    /// <returns></returns>
    /// <exception cref="System.ArgumentNullException">
    /// client
    /// or
    /// subject
    /// </exception>
    public async Task UpdateConsentAsync(ClaimsPrincipal subject, Client client, IEnumerable<ParsedScopeValue> parsedScopes)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (subject == null) throw new ArgumentNullException(nameof(subject));

        if (client.AllowRememberConsent)
        {
            var subjectId = subject.GetSubjectId();
            var clientId = client.ClientId;

            var scopes = parsedScopes.Select(x => x.Name).ToArray();
            if (scopes.Any())
            {
                logger.LogDebug("Client allows remembering consent, and consent given. Updating consent store for subject: {Subject}", subject.GetSubjectId());

                var consent = new Consent
                {
                    CreationTime = clock.UtcNow.UtcDateTime,
                    SubjectId = subjectId,
                    ClientId = clientId,
                    Scopes = scopes
                };

                if (client.ConsentLifetime.HasValue)
                {
                    consent.Expiration = consent.CreationTime.AddSeconds(client.ConsentLifetime.Value);
                }

                await userConsentStore.StoreUserConsentAsync(consent);
            }
            else
            {
                logger.LogDebug("Client allows remembering consent, and no scopes provided. Removing consent from consent store for subject: {Subject}", subject.GetSubjectId());

                await userConsentStore.RemoveUserConsentAsync(subjectId, clientId);
            }
        }
    }
}