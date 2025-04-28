using DotnetAuth.Domain.Contracts;

namespace DotnetAuth.Service
{
    public interface IActivityLoggingService
    {
        Task LogActivityAsync(string userId, string activityType, string description, string ipAddress = null);
        Task<AccountActivityResponse> GetUserActivitiesAsync(string userId, int take = 20);
        Task LogLoginAttemptAsync(string userId, bool wasSuccessful, string ipAddress, string device, string location);
    }
}