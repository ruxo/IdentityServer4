global using System.Threading.Tasks;
global using System.Collections.Generic;

global using LanguageExt;
global using RZ.Foundation.Extensions;
global using static LanguageExt.Prelude;

global using Array = System.Array;
global using ApiParameters = System.Collections.Immutable.ImmutableDictionary<string, Microsoft.Extensions.Primitives.StringValues>;
global using PersistableApiParameters = System.Collections.Generic.IDictionary<string, string[]>;

using Microsoft.AspNetCore.Http;

namespace IdentityServer4;

/// <summary>
/// Represent API response renderer
/// </summary>
public delegate Task<Unit> ApiRenderer(HttpContext context);