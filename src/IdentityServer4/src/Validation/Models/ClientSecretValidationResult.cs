// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Validation;

/// <summary>
/// Validation result for client validation
/// </summary>
/// <param name="Secret">the secret used to authenticate the client.</param>
/// <param name="Confirmation">the value of the confirmation method (will become the cnf claim). Must be a JSON object.</param>
public sealed record ClientSecretValidationResult(Client Client, ParsedSecret Secret, string Confirmation);