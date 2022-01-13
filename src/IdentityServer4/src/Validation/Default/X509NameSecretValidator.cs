using System;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using static IdentityServer4.IdentityServerConstants;
#pragma warning disable CS1998

namespace IdentityServer4.Validation.Default;

/// <summary>
/// Validator for an X.509 certificate based client secret using the common name
/// </summary>
public class X509NameSecretValidator : ISecretValidator
{
    readonly ILogger<X509NameSecretValidator> logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="logger"></param>
    public X509NameSecretValidator(ILogger<X509NameSecretValidator> logger)
    {
        this.logger = logger;
    }

    /// <inheritdoc/>
    public async ValueTask<Option<SecretInfo>> ValidateAsync(IEnumerable<Secret> secrets, Credentials credentials)
    {
        if (credentials is not Credentials.X509Certificate(_, var certificate))
            return None;

        var name = certificate.Subject;
        var nameSecrets = secrets.Where(s => s.Type == SecretTypes.X509CertificateName);

        if (nameSecrets.Any(nameSecret => name.Equals(nameSecret.Value, StringComparison.Ordinal)))
            return new SecretInfo(certificate.CreateThumbprintCnf());

        logger.LogDebug("No matching x509 name secret found");
        return None;
    }
}