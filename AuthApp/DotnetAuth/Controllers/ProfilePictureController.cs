using DotnetAuth.Domain.Contracts;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers
{
    [Authorize]
    [Route("api/profile-pictures")]
    [ApiController]
    public class ProfilePictureController : ControllerBase
    {
        private readonly IProfilePictureService _profilePictureService;
        private readonly ICurrentUserService _currentUserService;
        private readonly ILogger<ProfilePictureController> _logger;
        private readonly IActivityLoggingService _activityLoggingService;

        public ProfilePictureController(
            IProfilePictureService profilePictureService,
            ICurrentUserService currentUserService,
            ILogger<ProfilePictureController> logger,
            IActivityLoggingService activityLoggingService)
        {
            _profilePictureService = profilePictureService;
            _currentUserService = currentUserService;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
        }

        /// <summary>
        /// Upload a new profile picture
        /// </summary>
        [HttpPost("upload")]
        public async Task<ActionResult<ProfilePictureResponse>> UploadProfilePicture([FromForm] UploadProfilePictureRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized();
                }

                var result = await _profilePictureService.UploadProfilePictureAsync(userId, request.Picture);
                if (!result.Success)
                {
                    await _activityLoggingService.LogActivityAsync(userId, "Profile Picture Upload Failed", 
                        $"Failed to upload profile picture: {result.Message}");
                    return BadRequest(result);
                }

                await _activityLoggingService.LogActivityAsync(userId, "Profile Picture Upload API",
                    $"Successfully uploaded profile picture via API: {result.FileName}");
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading profile picture");
                var userId = _currentUserService.GetUserId();
                if (!string.IsNullOrEmpty(userId))
                {
                    await _activityLoggingService.LogActivityAsync(userId, "Profile Picture Upload Error",
                        "An error occurred while uploading the profile picture");
                }
                return StatusCode(500, new ProfilePictureResponse
                {
                    Success = false,
                    Message = "An error occurred while uploading the profile picture"
                });
            }
        }

        /// <summary>
        /// Get the current user's profile picture
        /// </summary>
        [HttpGet("current")]
        public async Task<ActionResult<ProfilePictureResponse>> GetCurrentProfilePicture()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized();
                }

                var result = await _profilePictureService.GetCurrentProfilePictureAsync(userId);
                await _activityLoggingService.LogActivityAsync(userId, "Profile Picture View",
                    "Viewed current profile picture");
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving current profile picture");
                var userId = _currentUserService.GetUserId();
                if (!string.IsNullOrEmpty(userId))
                {
                    await _activityLoggingService.LogActivityAsync(userId, "Profile Picture View Error",
                        "An error occurred while retrieving the profile picture");
                }
                return StatusCode(500, new ProfilePictureResponse
                {
                    Success = false,
                    Message = "An error occurred while retrieving the profile picture"
                });
            }
        }

        /// <summary>
        /// Get the profile picture history for the current user
        /// </summary>
        [HttpGet("history")]
        public async Task<ActionResult<ProfilePictureHistoryResponse>> GetProfilePictureHistory()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized();
                }

                var result = await _profilePictureService.GetProfilePictureHistoryAsync(userId);
                await _activityLoggingService.LogActivityAsync(userId, "Profile Picture History View",
                    "Viewed profile picture history");
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile picture history");
                var userId = _currentUserService.GetUserId();
                if (!string.IsNullOrEmpty(userId))
                {
                    await _activityLoggingService.LogActivityAsync(userId, "Profile Picture History Error",
                        "An error occurred while retrieving profile picture history");
                }
                return StatusCode(500, new ProfilePictureHistoryResponse
                {
                    History = new List<ProfilePictureHistoryEntry>()
                });
            }
        }
    }
}