using IdentityServer4.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Verified client with the given credentials
/// </summary>
/// <param name="Secret">the secret used to authenticate the client.</param>
/// <param name="Confirmation">the value of the confirmation method (will become the cnf claim). Must be a JSON object.</param>
public sealed record VerifiedClient(Client Client, ClientSecret Secret, Option<string> Confirmation);