namespace DotnetAuth.Service
{
    public interface ITokenBlacklistService
    {
        Task BlacklistTokenAsync(string token, DateTime expiryTime);
        Task<bool> IsTokenBlacklistedAsync(string token);
        Task CleanupExpiredTokensAsync();
    }
}