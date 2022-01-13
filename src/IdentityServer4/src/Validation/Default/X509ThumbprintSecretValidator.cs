using System;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using static IdentityServer4.IdentityServerConstants;
#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validator for an X.509 certificate based client secret using the thumbprint
/// </summary>
public class X509ThumbprintSecretValidator : ISecretValidator
{
    readonly ILogger<X509ThumbprintSecretValidator> logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="logger"></param>
    public X509ThumbprintSecretValidator(ILogger<X509ThumbprintSecretValidator> logger)
    {
        this.logger = logger;
    }

    /// <inheritdoc/>
    public async ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials)
    {
        if (credentials is not Credentials.X509Certificate(_, var cert))
            return None;

        var thumbprint = cert.Thumbprint;
        var thumbprintSecrets = secrets.Where(s => s.Type == SecretTypes.X509CertificateThumbprint);

        if (thumbprintSecrets.Any(thumbprintSecret => thumbprint.Equals(thumbprintSecret.Value, StringComparison.OrdinalIgnoreCase)))
            return new SecretInfo(cert.CreateThumbprintCnf());

        logger.LogDebug("No matching x509 thumbprint secret found");
        return None;
    }
}