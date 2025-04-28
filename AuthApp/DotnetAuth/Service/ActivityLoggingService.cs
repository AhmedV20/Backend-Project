using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Microsoft.EntityFrameworkCore;

namespace DotnetAuth.Service
{
    public class ActivityLoggingService : IActivityLoggingService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ActivityLoggingService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public ActivityLoggingService(
            ApplicationDbContext context,
            ILogger<ActivityLoggingService> logger,
            IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogActivityAsync(string userId, string activityType, string description, string ipAddress = null)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress))
                {
                    ipAddress = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "Unknown";
                }

                var activity = new AccountActivity
                {
                    UserId = userId,
                    ActivityType = activityType,
                    Description = description,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = ipAddress
                };

                _context.AccountActivities.Add(activity);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Activity logged: {ActivityType} for user {UserId}", activityType, userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging activity for user {UserId}", userId);
                throw;
            }
        }

        public async Task<AccountActivityResponse> GetUserActivitiesAsync(string userId, int take = 20)
        {
            try
            {
                var activities = await _context.AccountActivities
                    .Where(a => a.UserId == userId)
                    .OrderByDescending(a => a.Timestamp)
                    .Take(take)
                    .Select(a => new AccountActivityEntry
                    {
                        Timestamp = a.Timestamp,
                        ActivityType = a.ActivityType,
                        Description = a.Description,
                        IpAddress = a.IpAddress
                    })
                    .ToListAsync();

                return new AccountActivityResponse { Activities = activities };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving activities for user {UserId}", userId);
                throw;
            }
        }

        public async Task LogLoginAttemptAsync(string userId, bool wasSuccessful, string ipAddress, string device, string location)
        {
            try
            {
                var loginHistory = new LoginHistory
                {
                    UserId = userId,
                    LoginTime = DateTime.UtcNow,
                    IpAddress = ipAddress,
                    Device = device,
                    Location = location,
                    WasSuccessful = wasSuccessful
                };

                _context.LoginHistory.Add(loginHistory);

                // Also log as an activity
                await LogActivityAsync(
                    userId,
                    wasSuccessful ? "Login Success" : "Login Failed",
                    $"Login attempt from {device} at {location}",
                    ipAddress
                );

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging login attempt for user {UserId}", userId);
                throw;
            }
        }
    }
}