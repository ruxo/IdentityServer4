// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LanguageExt;
using RZ.Foundation.Extensions;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Services
{
    /// <summary>
    /// Default implementation of logout notification service.
    /// </summary>
    public class LogoutNotificationService : ILogoutNotificationService
    {
        private readonly IClientStore _clientStore;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<LogoutNotificationService> _logger;


        /// <summary>
        /// Ctor.
        /// </summary>
        public LogoutNotificationService(
            IClientStore clientStore,
            IHttpContextAccessor httpContextAccessor, 
            ILogger<LogoutNotificationService> logger)
        {
            _clientStore = clientStore;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        Option<string> GetRedirectUrl(LogoutNotificationContext context, Client client)
        {
            if (!client.FrontChannelLogoutUri.IsPresent())
                return None;
            
            var url = client.FrontChannelLogoutUri!;

            switch (client.ProtocolType) {
                // add session id if required
                case IdentityServerConstants.ProtocolTypes.OpenIdConnect:
                {
                    if (client.FrontChannelLogoutSessionRequired)
                    {
                        url = url.AddQueryString(OidcConstants.EndSessionRequest.Sid, context.SessionId);
                        url = url.AddQueryString(OidcConstants.EndSessionRequest.Issuer,
                            _httpContextAccessor.HttpContext!.GetIdentityServerIssuerUri());
                    }
                    break;
                }
                case IdentityServerConstants.ProtocolTypes.WsFederation:
                    url = url.AddQueryString(Constants.WsFedSignOut.LogoutUriParameterName,
                                             Constants.WsFedSignOut.LogoutUriParameterValue);
                    break;
            }
            return url;
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<string>> GetFrontChannelLogoutNotificationsUrlsAsync(LogoutNotificationContext context)
        {
            var frontChannelUrls = await context.ClientIds
                .ChooseAsync(_clientStore.FindEnabledClientByIdAsync)
                .Choose(c => GetRedirectUrl(context, c))
                .ToArrayAsync();

            if (frontChannelUrls.Any())
            {
                var msg = frontChannelUrls.Aggregate((x, y) => x + ", " + y);
                _logger.LogDebug("Client front-channel logout URLs: {Message}", msg);
            }
            else
                _logger.LogDebug("No client front-channel logout URLs");

            return frontChannelUrls;
        }

        Option<BackChannelLogoutRequest> GetBackChannelLogoutUri(LogoutNotificationContext context, string clientId,
            Client client) =>
            client.BackChannelLogoutUri.IsPresent()
                ? new BackChannelLogoutRequest
                {
                    ClientId = clientId,
                    LogoutUri = client.BackChannelLogoutUri!,
                    SubjectId = context.SubjectId,
                    SessionId = context.SessionId,
                    SessionIdRequired = client.BackChannelLogoutSessionRequired
                }
                : None;

        /// <inheritdoc/>
        public async Task<IEnumerable<BackChannelLogoutRequest>> GetBackChannelLogoutNotificationsAsync(LogoutNotificationContext context)
        {
            var backChannelLogouts = await context.ClientIds
                .ChooseAsync(_clientStore.FindClientByIdAsync)
                .Choose(c => GetBackChannelLogoutUri(context, c.ClientId!, c))
                .ToArrayAsync();

            if (backChannelLogouts.Any())
            {
                var msg = backChannelLogouts.Select(x => x.LogoutUri).Aggregate((x, y) => x + ", " + y);
                _logger.LogDebug("Client back-channel logout URLs: {Message}", msg);
            }
            else
                _logger.LogDebug("No client back-channel logout URLs");

            return backChannelLogouts;
        }
    }
}