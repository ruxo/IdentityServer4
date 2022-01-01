// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using RZ.Foundation.Helpers;

namespace IdentityServer4.Extensions;

static class ClaimsExtensions
{
    public static (Dictionary<string, object[]> Claims, Claim[] Invalid) ToClaimsDictionary(this IEnumerable<Claim> claims) {
        var d = new Dictionary<string, object[]>();
        var invalid = new List<Claim>();

        var groupClaims = from c in claims.Distinct(new ClaimComparer())
                          group c by c.Type into g
                          select g;

        foreach (var g in groupClaims) {
            var (validClaims, invalidClaims) = g.Map(claim => (claim, value: GetValue(claim)))
                                                .Partition(v => v.value.IsSome, v => v.value.Get(), v => v.claim);
            invalid.AddRange(invalidClaims);
            d.Add(g.Key, validClaims);
        }
        return (d, invalid.ToArray());
    }

    static Option<object> GetValue(Claim claim) =>
        claim.ValueType switch{
            ClaimValueTypes.Integer or ClaimValueTypes.Integer32 => TryConvert.ToInt32(claim.Value).Map(x => (object)x),
            ClaimValueTypes.Integer64                            => TryConvert.ToInt64(claim.Value).Map(x => (object)x),
            ClaimValueTypes.Boolean                              => TryConvert.ToBoolean(claim.Value).Map(x => (object)x),
            IdentityServerConstants.ClaimValueTypes.Json         => (object)JsonSerializer.Deserialize<JsonElement>(claim.Value),
            _                                                    => claim.Value
        };
}