using Microsoft.Extensions.Caching.Distributed;

namespace DotnetAuth.Service
{
    public class TokenBlacklistService : ITokenBlacklistService
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<TokenBlacklistService> _logger;

        public TokenBlacklistService(IDistributedCache cache, ILogger<TokenBlacklistService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        public async Task BlacklistTokenAsync(string token, DateTime expiryTime)
        {
            try
            {
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = expiryTime
                };

                await _cache.SetStringAsync(
                    $"blacklist_token_{token}",
                    DateTime.UtcNow.ToString("O"),
                    options
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blacklisting token");
                throw;
            }
        }

        public async Task<bool> IsTokenBlacklistedAsync(string token)
        {
            try
            {
                var blacklistedTime = await _cache.GetStringAsync($"blacklist_token_{token}");
                return blacklistedTime != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking blacklisted token");
                return false;
            }
        }

        public async Task CleanupExpiredTokensAsync()
        {
            // The distributed cache automatically handles cleanup of expired items
            await Task.CompletedTask;
        }
    }
}