using DotnetAuth.Domain.Contracts;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers
{
    /// <summary>
    /// Controller for handling authentication-related operations.
    /// </summary>
    [Route("api/")]
    public class AuthController : ControllerBase
    {
        private readonly IUserServices _userService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthController> _logger;
        private readonly IActivityLoggingService _activityLoggingService;
        private readonly ICurrentUserService _currentUserService;

        public AuthController(
            IUserServices userService,
            ITokenService tokenService,
            ILogger<AuthController> logger,
            IActivityLoggingService activityLoggingService,
            ICurrentUserService currentUserService)
        {
            _userService = userService;
            _tokenService = tokenService;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
            _currentUserService = currentUserService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            var response = await _userService.RegisterAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Registration",
                    "New user registration completed");
            }
            return Ok(response);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<UserResponse>> Login([FromBody] UserLoginRequest request)
        {
            try
            {
                var response = await _userService.LoginAsync(request);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("verify-otp")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
        {
            var response = await _userService.VerifyOtpAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Email Verification",
                    "Email verified successfully");
            }
            return Ok(response);
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var response = await _userService.ForgotPasswordAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Password Reset Initiated",
                    "Password reset process initiated");
            }
            return Ok(response);
        }

        [HttpPost("reset-password")]
        [Authorize]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var response = await _userService.ResetPasswordAsync(request);
            var userId = _currentUserService.GetUserId();
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Password Reset Complete",
                    "Password was successfully reset");
            }
            return Ok(response);
        }

        [HttpPost("change-email")]
        [Authorize]
        public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.ChangeEmailAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Email Change Initiated",
                    $"Email change requested to: {request.NewEmail}");
            }
            return Ok(response);
        }

        [HttpPost("update-phone")]
        [Authorize]
        public async Task<ActionResult<UpdatePhoneNumberResponse>> UpdatePhoneNumber([FromBody] UpdatePhoneNumberRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.UpdatePhoneNumberAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Phone Update Initiated",
                    $"Phone number update requested to: {request.PhoneNumber}");
            }
            return Ok(response);
        }

        [HttpPost("verify-phone")]
        [Authorize]
        public async Task<ActionResult<VerifyPhoneNumberResponse>> VerifyPhoneNumber([FromBody] VerifyPhoneNumberRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.VerifyPhoneNumberAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Phone Verification",
                    $"Phone number verified: {request.PhoneNumber}");
            }
            return Ok(response);
        }

        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var response = await _userService.GetCurrentUserAsync();
            await _activityLoggingService.LogActivityAsync(
                response.Id,
                "Profile View",
                "User viewed their profile");
            return Ok(response);
        }

        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetById(Guid id)
        {
            var response = await _userService.GetByIdAsync(id);
            var currentUserId = _currentUserService.GetUserId();
            await _activityLoggingService.LogActivityAsync(
                currentUserId,
                "User Lookup",
                $"Viewed user profile: {id}");
            return Ok(response);
        }

        [HttpDelete("user/{id}")]
        [Authorize]
        public async Task<IActionResult> Delete(Guid id)
        {
            var currentUserId = _currentUserService.GetUserId();
            await _userService.DeleteAsync(id);
            await _activityLoggingService.LogActivityAsync(
                currentUserId,
                "Account Deletion",
                $"Deleted user account: {id}");
            return Ok();
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                var userId = _currentUserService.GetUserId();
                
                if (!string.IsNullOrEmpty(token))
                {
                    await _tokenService.RevokeTokenAsync(token);
                    await _activityLoggingService.LogActivityAsync(
                        userId,
                        "Logout",
                        "User logged out successfully");
                    return Ok(new { Message = "Logged out successfully" });
                }
                return BadRequest(new { Message = "No token provided" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return BadRequest(new { Message = "Error processing logout" });
            }
        }

        [HttpGet("login-history")]
        [Authorize]
        public async Task<ActionResult<LoginHistoryResponse>> GetLoginHistory()
        {
            try
            {
                var response = await _userService.GetLoginHistoryAsync();
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving login history");
                return BadRequest(new ErrorResponse { Message = ex.Message });
            }
        }

        [HttpGet("account-activity")]
        [Authorize]
        public async Task<ActionResult<AccountActivityResponse>> GetAccountActivity()
        {
            try
            {
                var response = await _userService.GetAccountActivitiesAsync();
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving account activities");
                return BadRequest(new ErrorResponse { Message = ex.Message });
            }
        }
    }
}
