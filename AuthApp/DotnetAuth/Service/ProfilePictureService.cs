using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DotnetAuth.Service
{
    public class ProfilePictureService : IProfilePictureService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<ProfilePictureService> _logger;
        private readonly IActivityLoggingService _activityLoggingService;

        public ProfilePictureService(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            IWebHostEnvironment environment,
            ILogger<ProfilePictureService> logger,
            IActivityLoggingService activityLoggingService)
        {
            _context = context;
            _userManager = userManager;
            _environment = environment;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
        }

        public async Task<ProfilePictureResponse> UploadProfilePictureAsync(string userId, IFormFile file)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return new ProfilePictureResponse 
                    { 
                        Success = false, 
                        Message = "User not found" 
                    };
                }

                // Deactivate current profile picture
                var currentPicture = await _context.UserProfilePictures
                    .Where(p => p.UserId == userId && p.IsActive)
                    .FirstOrDefaultAsync();

                if (currentPicture != null)
                {
                    currentPicture.IsActive = false;
                    _context.UserProfilePictures.Update(currentPicture);
                }

                // Create unique filename
                var fileName = $"{userId}_{DateTime.Now.Ticks}_{file.FileName}";
                var filePath = Path.Combine("profile-pictures", fileName);
                var fullPath = Path.Combine(_environment.WebRootPath, filePath);

                var directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                using (var stream = new FileStream(fullPath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var profilePicture = new UserProfilePicture
                {
                    UserId = userId,
                    FileName = fileName,
                    ContentType = file.ContentType,
                    FilePath = $"/{filePath.Replace("\\", "/")}",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                await _context.UserProfilePictures.AddAsync(profilePicture);
                await _context.SaveChangesAsync();

                // Log the activity
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Profile Picture Update",
                    $"Updated profile picture: {fileName}");

                return new ProfilePictureResponse
                {
                    Success = true,
                    Message = "Profile picture uploaded successfully",
                    FileName = fileName,
                    FileUrl = profilePicture.FilePath,
                    UploadDate = profilePicture.CreatedAt
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading profile picture for user {UserId}", userId);
                return new ProfilePictureResponse
                {
                    Success = false,
                    Message = "Error uploading profile picture"
                };
            }
        }

        public async Task<ProfilePictureResponse> GetCurrentProfilePictureAsync(string userId)
        {
            try
            {
                var currentPicture = await _context.UserProfilePictures
                    .Where(p => p.UserId == userId && p.IsActive)
                    .FirstOrDefaultAsync();

                if (currentPicture == null)
                {
                    var defaultPicture = await GetDefaultProfilePictureAsync();
                    return new ProfilePictureResponse
                    {
                        Success = true,
                        Message = "Default profile picture",
                        FileName = defaultPicture.FileName,
                        FileUrl = defaultPicture.FilePath
                    };
                }

                return new ProfilePictureResponse
                {
                    Success = true,
                    Message = "Profile picture retrieved successfully",
                    FileName = currentPicture.FileName,
                    FileUrl = currentPicture.FilePath,
                    UploadDate = currentPicture.CreatedAt
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile picture for user {UserId}", userId);
                return new ProfilePictureResponse
                {
                    Success = false,
                    Message = "Error retrieving profile picture"
                };
            }
        }

        public async Task<ProfilePictureHistoryResponse> GetProfilePictureHistoryAsync(string userId)
        {
            try
            {
                var history = await _context.UserProfilePictures
                    .Where(p => p.UserId == userId)
                    .OrderByDescending(p => p.CreatedAt)
                    .Select(p => new ProfilePictureHistoryEntry
                    {
                        FileName = p.FileName,
                        FileUrl = p.FilePath,
                        UploadDate = p.CreatedAt,
                        IsActive = p.IsActive
                    })
                    .ToListAsync();

                return new ProfilePictureHistoryResponse
                {
                    History = history
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile picture history for user {UserId}", userId);
                return new ProfilePictureHistoryResponse
                {
                    History = new List<ProfilePictureHistoryEntry>()
                };
            }
        }

        public async Task<string> AssignDefaultProfilePictureAsync(string userId)
        {
            try
            {
                var defaultPicture = await GetDefaultProfilePictureAsync();
                var profilePicture = new UserProfilePicture
                {
                    UserId = userId,
                    FileName = defaultPicture.FileName,
                    ContentType = defaultPicture.ContentType,
                    FilePath = defaultPicture.FilePath,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                await _context.UserProfilePictures.AddAsync(profilePicture);
                await _context.SaveChangesAsync();

                // Log the activity
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Default Profile Picture Assigned",
                    "Assigned default profile picture");

                return defaultPicture.FilePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assigning default profile picture for user {UserId}", userId);
                return string.Empty;
            }
        }

        public async Task<bool> DeleteProfilePictureAsync(string userId, int pictureId)
        {
            try
            {
                var picture = await _context.UserProfilePictures
                    .FirstOrDefaultAsync(p => p.Id == pictureId && p.UserId == userId);

                if (picture == null)
                {
                    return false;
                }

                if (picture.IsActive)
                {
                    await AssignDefaultProfilePictureAsync(userId);
                }

                _context.UserProfilePictures.Remove(picture);
                await _context.SaveChangesAsync();

                if (!picture.FilePath.Contains("defaults") && 
                    File.Exists(Path.Combine(_environment.WebRootPath, picture.FilePath.TrimStart('/'))))
                {
                    File.Delete(Path.Combine(_environment.WebRootPath, picture.FilePath.TrimStart('/')));
                }

                // Log the activity
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Profile Picture Delete",
                    $"Deleted profile picture: {picture.FileName}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting profile picture {PictureId} for user {UserId}", pictureId, userId);
                return false;
            }
        }

        private async Task<UserDefaultProfilePicture> GetDefaultProfilePictureAsync()
        {
            var defaultPicture = await _context.UserDefaultProfilePictures
                .FirstOrDefaultAsync(p => p.IsActive);

            if (defaultPicture == null)
            {
                // Create default if it doesn't exist
                defaultPicture = new UserDefaultProfilePicture
                {
                    FileName = "default-picture-profile.png",
                    ContentType = "image/png",
                    FilePath = "/profile-pictures/defaults/default-picture-profile.png",
                    IsActive = true
                };

                await _context.UserDefaultProfilePictures.AddAsync(defaultPicture);
                await _context.SaveChangesAsync();
            }

            return defaultPicture;
        }
    }
}