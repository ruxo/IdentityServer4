using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.Extensions.Caching.Distributed;

namespace IdentityServer4.Stores.Default;

/// <summary>
/// Implementation of IAuthorizationParametersMessageStore that uses the IDistributedCache.
/// </summary>
// ReSharper disable once UnusedType.Global
public class DistributedCacheAuthorizationParametersMessageStore : IAuthorizationParametersMessageStore
{
    readonly IDistributedCache distributedCache;
    readonly IHandleGenerationService handleGenerationService;

    /// <summary>
    /// Ctor.
    /// </summary>
    /// <param name="distributedCache"></param>
    /// <param name="handleGenerationService"></param>
    public DistributedCacheAuthorizationParametersMessageStore(IDistributedCache distributedCache, IHandleGenerationService handleGenerationService)
    {
        this.distributedCache = distributedCache;
        this.handleGenerationService = handleGenerationService;
    }

    string CacheKeyPrefix => "DistributedCacheAuthorizationParametersMessageStore";

    /// <inheritdoc/>
    public async Task<string> WriteAsync(Message<IDictionary<string, string[]>> message)
    {
        // since this store is trusted and the JWT request processing has provided redundant entries
        // in the Dictionary<string,string>, we are removing the JWT "request_uri" param so that when they
        // are reloaded/revalidated we don't re-trigger outbound requests. we could possibly do the
        // same for the "request" param, but it's less of a concern (as it's just a signature check).
        message.Data.Remove(OidcConstants.AuthorizeRequest.RequestUri);

        var key = await handleGenerationService.GenerateAsync();
        var cacheKey = $"{CacheKeyPrefix}-{key}";

        var json = ObjectSerializer.ToString(message);

        var options = new DistributedCacheEntryOptions();
        options.SetSlidingExpiration(Constants.DefaultCacheDuration);

        await distributedCache.SetStringAsync(cacheKey, json, options);

        return key;
    }

    /// <inheritdoc/>
    public async Task<Message<IDictionary<string, string[]>>> ReadAsync(string id)
    {
        var cacheKey = $"{CacheKeyPrefix}-{id}";
        var json = await distributedCache.GetStringAsync(cacheKey);

        return json == null
                   ? Message.Create((IDictionary<string, string[]>)new Dictionary<string, string[]>())
                   : ObjectSerializer.FromString<Message<IDictionary<string, string[]>>>(json);
    }

    /// <inheritdoc/>
    public Task DeleteAsync(string id)
    {
        return distributedCache.RemoveAsync(id);
    }
}