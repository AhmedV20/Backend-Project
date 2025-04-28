using AutoMapper;
using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace DotnetAuth.Service
{
    /// <summary>
    /// Implementation of the IUserServices interface for managing user-related operations.
    /// </summary>
    public class UserServiceImpl : IUserServices
    {
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        private readonly ILogger<UserServiceImpl> _logger;
        private readonly IEmailService _emailService;
        private readonly ApplicationDbContext _context;
        private readonly IServiceProvider _serviceProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IActivityLoggingService _activityLoggingService;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserServiceImpl"/> class.
        /// </summary>
        /// <param name="tokenService">The token service for generating tokens.</param>
        /// <param name="currentUserService">The current user service for retrieving current user information.</param>
        /// <param name="userManager">The user manager for managing user information.</param>
        /// <param name="mapper">The mapper for mapping objects.</param>
        /// <param name="logger">The logger for logging information.</param>
        /// <param name="emailService">The email service for sending emails.</param>
        /// <param name="context">The application database context.</param>
        /// <param name="serviceProvider">The service provider for resolving services.</param>
        /// <param name="httpContextAccessor">The HTTP context accessor for accessing HTTP context.</param>
        public UserServiceImpl(
            ITokenService tokenService,
            ICurrentUserService currentUserService,
            UserManager<ApplicationUser> userManager,
            IMapper mapper,
            ILogger<UserServiceImpl> logger,
            IEmailService emailService,
            ApplicationDbContext context,
            IServiceProvider serviceProvider,
            IHttpContextAccessor httpContextAccessor,
            IActivityLoggingService activityLoggingService)
        {
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
            _emailService = emailService;
            _context = context;
            _serviceProvider = serviceProvider;
            _httpContextAccessor = httpContextAccessor;
            _activityLoggingService = activityLoggingService;
        }

        /// <summary>
        /// Registers a new user.
        /// </summary>
        /// <param name="request">The user registration request.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the user response.</returns>
        /// <exception cref="Exception">Thrown when the email already exists or user creation fails.</exception>
        public async Task<UserRegisterResponse> RegisterAsync(UserRegisterRequest request)
        {
            try
            {
                if (request == null)
                {
                    _logger.LogError("Registration request is null");
                    return new UserRegisterResponse
                    {
                        Success = false,
                        Message = "Invalid registration request"
                    };
                }

                if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                {
                    return new UserRegisterResponse
                    {
                        Success = false,
                        Message = "Email and password are required"
                    };
                }

                _logger.LogInformation("Registering user");
                var existingUser = await _userManager.FindByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return new UserRegisterResponse
                    {
                        Success = false,
                        Message = "Email already exists"
                    };
                }

                var newUser = _mapper.Map<ApplicationUser>(request);
                if (newUser == null)
                {
                    _logger.LogError("Failed to map user registration request");
                    return new UserRegisterResponse
                    {
                        Success = false,
                        Message = "Error processing registration request"
                    };
                }

                newUser.Role = request.Role.ToString();
                newUser.Gender = request.Gender;
                newUser.UserName = GenerateUserName(request.FirstName, request.LastName);
                newUser.CreateAt = DateTime.Now;
                newUser.UpdateAt = DateTime.Now;
                newUser.IsEmailConfirmed = false;
                newUser.EmailConfirmed = false;

                // Generate OTP for immediate email verification
                var otp = GenerateSecureOtp();
                newUser.Otp = otp;
                newUser.OtpExpiryTime = DateTime.UtcNow.AddMinutes(15);

                var result = await _userManager.CreateAsync(newUser, request.Password);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to create user: {errors}", errors);
                    return new UserRegisterResponse
                    {
                        Success = false,
                        Message = $"Failed to create user: {errors}"
                    };
                }

                // Add user to role
                await _userManager.AddToRoleAsync(newUser, request.Role.ToString());

                // Assign default profile picture
                var profilePictureService = _serviceProvider.GetRequiredService<IProfilePictureService>();
                await profilePictureService.AssignDefaultProfilePictureAsync(newUser.Id);

                // Send verification email
                var subject = "Email Verification OTP";
                var body = $@"
                    <h2>Welcome to Our Application!</h2>
                    <p>Thank you for registering. Your OTP for email verification is: <strong>{otp}</strong></p>
                    <p>This OTP will expire in 15 minutes.</p>
                    <p>If you didn't register for an account, please ignore this email.</p>";

                var emailSent = await _emailService.SendEmailAsync(newUser.Email, subject, body);
                if (!emailSent)
                {
                    _logger.LogError("Failed to send verification email");
                }

                _logger.LogInformation("User registered successfully");
                return new UserRegisterResponse
                {
                    Success = true,
                    Message = "Registration successful. Please verify your email with the OTP sent to your email address.",
                    Otp = otp, // Remove this in production
                    UserId = newUser.Id
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");
                return new UserRegisterResponse
                {
                    Success = false,
                    Message = "An error occurred during registration"
                };
            }
        }

        /// <summary>
        /// Generates a unique username by concatenating the first name and last name.
        /// </summary>
        /// <param name="firstName">The first name of the user.</param>
        /// <param name="lastName">The last name of the user.</param>
        /// <returns>The generated unique username.</returns>
        private string GenerateUserName(string firstName, string lastName)
        {
            var baseUsername = $"{firstName}{lastName}".ToLower();

            // Check if the username already exists
            var username = baseUsername;
            var count = 1;
            while (_userManager.Users.Any(u => u.UserName == username))
            {
                username = $"{baseUsername}{count}";
                count++;
            }
            return username;
        }

        private string GenerateSecureOtp()
        {
            using var rng = RandomNumberGenerator.Create();
            var randomNumber = new byte[4];
            rng.GetBytes(randomNumber);
            var otpValue = BitConverter.ToUInt32(randomNumber, 0) % 1000000;
            return otpValue.ToString("D6");
        }

        /// <summary>
        /// Logs in a user.
        /// </summary>
        /// <param name="request">The user login request.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the user response.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the login request is null.</exception>
        /// <exception cref="Exception">Thrown when the email or password is invalid or user update fails.</exception>
        public async Task<UserResponse> LoginAsync(UserLoginRequest request)
        {
            try
            {
                if (request == null)
                {
                    _logger.LogError("Login request is null");
                    throw new ArgumentNullException(nameof(request));
                }

                var user = await _userManager.FindByEmailAsync(request.Email);
                var isPasswordValid = user != null && await _userManager.CheckPasswordAsync(user, request.Password);

                if (!isPasswordValid)
                {
                    if (user != null)
                    {
                        // Track failed login attempt
                        await TrackLoginAttempt(user, false, "Unknown",
                            GetDeviceInfo(), GetLocationInfo());
                    }
                    _logger.LogError("Invalid email or password");
                    throw new Exception("Invalid email or password");
                }

                // Check if email is confirmed
                if (!user.IsEmailConfirmed)
                {
                    await TrackLoginAttempt(user, false, "Unknown",
                        GetDeviceInfo(), "Email not confirmed");
                    _logger.LogError("Email not confirmed");
                    throw new Exception("Please confirm your email before logging in");
                }

                // Generate access token
                var token = await _tokenService.GenerateToken(user);

                // Generate refresh token
                var refreshToken = _tokenService.GenerateRefreshToken();

                // Hash the refresh token and store it in the database
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
                user.RefreshToken = Convert.ToBase64String(refreshTokenHash);

                // Set refresh token expiry based on RememberMe
                user.RefreshTokenExpiryTime = request.RememberMe
                    ? DateTime.Now.AddDays(30)  // 30 days for "Remember Me"
                    : DateTime.Now.AddDays(1);  // 1 day for normal login

                // Only update the UpdateAt timestamp during login
                user.UpdateAt = DateTime.Now;

                // Update user information in database
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to update user: {errors}", errors);
                    throw new Exception($"Failed to update user: {errors}");
                }

                // Track successful login
                await TrackLoginAttempt(user, true, "Unknown",
                    GetDeviceInfo(), GetLocationInfo());

                // Track account activity
                await TrackAccountActivity(user.Id, "Login",
                    "Successful login to account", "Unknown");

                var userResponse = _mapper.Map<ApplicationUser, UserResponse>(user);
                userResponse.AccessToken = token;
                userResponse.RefreshToken = refreshToken;

                return userResponse;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                throw;
            }
        }

        private string GetDeviceInfo()
        {
            // In a real application, you would get this from the request headers
            return "Web Browser"; // Placeholder implementation
        }

        private string GetLocationInfo()
        {
            // In a real application, you would get this from IP geolocation
            return "Unknown"; // Placeholder implementation
        }

        /// <summary>
        /// Gets a user by ID.
        /// </summary>
        /// <param name="id">The ID of the user.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the user response.</returns>
        /// <exception cref="Exception">Thrown when the user is not found.</exception>
        public async Task<UserResponse> GetByIdAsync(Guid id)
        {
            _logger.LogInformation("Getting user by id");
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            _logger.LogInformation("User found");
            return _mapper.Map<UserResponse>(user);
        }

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation. The task result contains the current user response.</returns>
        /// <exception cref="Exception">Thrown when the user is not found.</exception>
        public async Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            var user = await _userManager.FindByIdAsync(_currentUserService.GetUserId());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            
            var response = _mapper.Map<CurrentUserResponse>(user);
            response.Id = user.Id; // Ensure Id is populated
            return response;
        }

        /// <summary>
        /// Refreshes the access token using the refresh token.
        /// </summary>
        /// <param name="request">The refresh token request.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the current user response.</returns>
        /// <exception cref="Exception">Thrown when the refresh token is invalid or expired.</exception>
        public async Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("RefreshToken");

            // Hash the incoming RefreshToken and compare it with the one stored in the database
            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(request.RefreshToken));
            var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

            // Find user based on the refresh token
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
            if (user == null)
            {
                _logger.LogError("Invalid refresh token");
                throw new Exception("Invalid refresh token");
            }

            // Validate the refresh token expiry time
            if (user.RefreshTokenExpiryTime < DateTime.Now)
            {
                _logger.LogWarning("Refresh token expired for user ID: {UserId}", user.Id);
                throw new Exception("Refresh token expired");
            }

            // Generate a new access token
            var newAccessToken = await _tokenService.GenerateToken(user);
            _logger.LogInformation("Access token generated successfully");
            var currentUserResponse = _mapper.Map<CurrentUserResponse>(user);
            currentUserResponse.AccessToken = newAccessToken;
            return currentUserResponse;
        }

        /// <summary>
        /// Revokes the refresh token.
        /// </summary>
        /// <param name="refreshTokenRemoveRequest">The refresh token request to be revoked.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the revoke refresh token response.</returns>
        /// <exception cref="Exception">Thrown when the refresh token is invalid or expired.</exception>
        public async Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest)
        {
            _logger.LogInformation("Revoking refresh token");

            try
            {
                // Hash the refresh token
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshTokenRemoveRequest.RefreshToken));
                var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

                // Find the user based on the refresh token
                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
                if (user == null)
                {
                    _logger.LogError("Invalid refresh token");
                    throw new Exception("Invalid refresh token");
                }

                // Validate the refresh token expiry time
                if (user.RefreshTokenExpiryTime < DateTime.Now)
                {
                    _logger.LogWarning("Refresh token expired for user ID: {UserId}", user.Id);
                    throw new Exception("Refresh token expired");
                }

                // Remove the refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                // Update user information in database
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to update user");
                    return new RevokeRefreshTokenResponse
                    {
                        Message = "Failed to revoke refresh token"
                    };
                }
                _logger.LogInformation("Refresh token revoked successfully");
                return new RevokeRefreshTokenResponse
                {
                    Message = "Refresh token revoked successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to revoke refresh token: {ex}", ex.Message);
                throw new Exception("Failed to revoke refresh token");
            }
        }

        /// <summary>
        /// Updates a user.
        /// </summary>
        /// <param name="id">The ID of the user to be updated.</param>
        /// <param name="request">The update user request.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the user response.</returns>
        /// <exception cref="Exception">Thrown when the user is not found.</exception>
        public async Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }

            user.UpdateAt = DateTime.Now;
            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.Email = request.Email;
            user.Gender = request.Gender;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to update user: {errors}", errors);
                throw new Exception($"Failed to update user: {errors}");
            }

            return _mapper.Map<UserResponse>(user);
        }

        /// <summary>
        /// Deletes a user.
        /// </summary>
        /// <param name="id">The ID of the user to be deleted.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="Exception">Thrown when the user is not found.</exception>
        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            await _userManager.DeleteAsync(user);
        }


        public async Task<VerifyOtpResponse> VerifyOtpAsync(VerifyOtpRequest request)
        {
            try
            {
                _logger.LogInformation("Starting OTP verification for email: {Email}", request.Email);

                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    _logger.LogWarning("User not found for email: {Email}", request.Email);
                    return new VerifyOtpResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                if (user.Otp != request.Otp)
                {
                    _logger.LogWarning("Invalid OTP provided for user: {Email}", request.Email);
                    return new VerifyOtpResponse
                    {
                        Success = false,
                        Message = "Invalid OTP"
                    };
                }

                if (user.OtpExpiryTime < DateTime.UtcNow)
                {
                    _logger.LogWarning("OTP expired for user: {Email}", request.Email);
                    return new VerifyOtpResponse
                    {
                        Success = false,
                        Message = "OTP has expired"
                    };
                }

                user.IsEmailConfirmed = true;
                user.EmailConfirmed = true;
                user.Otp = null;
                user.OtpExpiryTime = null;

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to update user after OTP verification: {Errors}", errors);
                    return new VerifyOtpResponse
                    {
                        Success = false,
                        Message = "Failed to confirm email"
                    };
                }

                var accessToken = await _tokenService.GenerateToken(user);
                _logger.LogInformation("OTP verification successful for user: {Email}", request.Email);

                return new VerifyOtpResponse
                {
                    Success = true,
                    Message = "Email confirmed successfully",
                    AccessToken = accessToken,
                    UserId = user.Id
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying OTP for email: {Email}", request?.Email);
                return new VerifyOtpResponse
                {
                    Success = false,
                    Message = "Error verifying OTP"
                };
            }
        }

        public async Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            try
            {
                if (request == null)
                {
                    _logger.LogError("Forgot password request is null");
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Invalid request"
                    };
                }

                if (string.IsNullOrEmpty(request.Email))
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Email is required"
                    };
                }

                if (string.IsNullOrEmpty(request.OldPassword))
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Old password is required"
                    };
                }

                if (string.IsNullOrEmpty(request.NewPassword))
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "New password is required"
                    };
                }

                if (string.IsNullOrEmpty(request.ConfirmPassword))
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Confirm password is required"
                    };
                }

                if (request.NewPassword != request.ConfirmPassword)
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "New password and confirm password do not match"
                    };
                }

                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Invalid email address"
                    };
                }

                // Verify old password
                if (!await _userManager.CheckPasswordAsync(user, request.OldPassword))
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "Invalid old password"
                    };
                }

                // Verify new password is different from old password
                if (request.OldPassword == request.NewPassword)
                {
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = "New password must be different from old password"
                    };
                }

                // Change password
                var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to change password: {errors}", errors);
                    return new ForgotPasswordResponse
                    {
                        Success = false,
                        Message = $"Failed to change password: {errors}"
                    };
                }

                // Revoke the current access token
                var currentToken = _currentUserService.GetCurrentAccessToken();
                if (!string.IsNullOrEmpty(currentToken))
                {
                    await _tokenService.RevokeTokenAsync(currentToken);
                }

                // Clear refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                // Send confirmation email
                var subject = "Password Changed Successfully - Forgot Password";
                var body = $@"
                    <h2>Password Change Confirmation</h2>
                    <p>Hello {user.FirstName},</p>
                    <p>Your password has been successfully changed using the Forgot Password feature.</p>
                    <p>This change was made on {DateTime.UtcNow:f} UTC.</p>
                    <p>If you did not make this change, please contact our support team immediately.</p>
                    <p>Security Tips:</p>
                    <ul>
                        <li>Never share your password with anyone</li>
                        <li>Use a unique password for each account</li>
                        <li>Enable two-factor authentication for additional security</li>
                    </ul>
                    <p>Best regards,<br>Your Application Team</p>";

                await _emailService.SendEmailAsync(user.Email, subject, body);

                _logger.LogInformation("Password changed successfully for user {Email}", request.Email);
                return new ForgotPasswordResponse
                {
                    Success = true,
                    Message = "Password has been changed successfully. Please log in again with your new password.",
                    UserId = user.Id
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in forgot password process for email: {Email}", request?.Email ?? "unknown");
                return new ForgotPasswordResponse
                {
                    Success = false,
                    Message = "An error occurred. Please try again later."
                };
            }
        }

        public async Task<VerifyResetOtpResponse> VerifyResetOtpAsync(VerifyResetOtpRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    return new VerifyResetOtpResponse
                    {
                        Success = false,
                        Message = "Invalid request"
                    };
                }

                if (user.Otp != request.Otp)
                {
                    return new VerifyResetOtpResponse
                    {
                        Success = false,
                        Message = "Invalid OTP"
                    };
                }

                if (user.OtpExpiryTime < DateTime.UtcNow)
                {
                    return new VerifyResetOtpResponse
                    {
                        Success = false,
                        Message = "OTP has expired"
                    };
                }

                // Generate a temporary token that will be valid for 5 minutes
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                return new VerifyResetOtpResponse
                {
                    Success = true,
                    Message = "OTP verified successfully",
                    ResetToken = resetToken // This will be needed for the actual password reset
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying reset OTP");
                return new VerifyResetOtpResponse
                {
                    Success = false,
                    Message = "An error occurred while verifying OTP"
                };
            }
        }

        public async Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordRequest request)
        {
            try
            {
                // Get the current user
                var userId = _currentUserService.GetUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "User not authenticated"
                    };
                }
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }
                // Validate that NewPassword and ConfirmPassword match
                if (request.NewPassword != request.ConfirmPassword)
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "New password and confirm password do not match"
                    };
                }

                // Check if the new password matches the current password
                var isCurrentPassword = await _userManager.CheckPasswordAsync(user, request.NewPassword);
                if (isCurrentPassword)
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "New password must be different from the current password"
                    };
                }

                // Reset password using password hasher
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = $"Failed to reset password: {errors}"
                    };
                }

                // Revoke the current access token
                var currentToken = _currentUserService.GetCurrentAccessToken();
                if (!string.IsNullOrEmpty(currentToken))
                {
                    await _tokenService.RevokeTokenAsync(currentToken);
                }

                // Clear refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                // Send confirmation email
                var subject = "Password Reset Confirmation";
                var body = $@"
                    <h2>Password Reset Confirmation</h2>
                    <p>Hello {user.FirstName},</p>
                    <p>Your password has been successfully reset.</p>
                    <p>This change was made on {DateTime.UtcNow:f} UTC.</p>
                    <p>Details:</p>
                    <ul>
                        <li>Account: {user.Email}</li>
                        <li>Action: Password Reset</li>
                        <li>Time: {DateTime.UtcNow:f} UTC</li>
                    </ul>
                    <p>If you did not request this password reset, please:</p>
                    <ol>
                        <li>Change your password immediately</li>
                        <li>Contact our support team</li>
                        <li>Review your account security settings</li>
                    </ol>
                    <p>For security reasons, we recommend:</p>
                    <ul>
                        <li>Using a strong, unique password</li>
                        <li>Enabling two-factor authentication</li>
                        <li>Regularly reviewing your account activity</li>
                    </ul>
                    <p>Best regards,<br>Your Application Security Team</p>";
                await _emailService.SendEmailAsync(user.Email, subject, body);

                return new ResetPasswordResponse
                {
                    Success = true,
                    Message = "Password has been reset successfully. Please log in again with your new password.",
                    UserId = user.Id
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return new ResetPasswordResponse
                {
                    Success = false,
                    Message = "An error occurred while resetting the password"
                };
            }
        }

        public async Task<ChangeEmailResponse> ChangeEmailAsync(ChangeEmailRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    _logger.LogError("User not found");
                    return new ChangeEmailResponse { Success = false, Message = "User not found" };
                }

                // Verify password
                if (!await _userManager.CheckPasswordAsync(user, request.Password))
                {
                    _logger.LogWarning("Invalid password provided for email change");
                    return new ChangeEmailResponse { Success = false, Message = "Invalid password" };
                }

                // Check if email is already in use
                var existingUser = await _userManager.FindByEmailAsync(request.NewEmail);
                if (existingUser != null)
                {
                    return new ChangeEmailResponse { Success = false, Message = "Email already in use" };
                }

                // Generate OTP for email verification
                var otp = GenerateSecureOtp();
                user.Otp = otp;
                user.OtpExpiryTime = DateTime.UtcNow.AddMinutes(15);

                // Store new email temporarily (will be applied after verification)
                await _userManager.SetEmailAsync(user, request.NewEmail);
                user.EmailConfirmed = false;
                user.IsEmailConfirmed = false;

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to update user: {errors}", errors);
                    return new ChangeEmailResponse { Success = false, Message = $"Failed to update email: {errors}" };
                }

                // Send verification email
                var subject = "Email Change Verification";
                var body = $@"
                    <h2>Email Change Request</h2>
                    <p>We received a request to change your email address. Your verification code is: <strong>{otp}</strong></p>
                    <p>This code will expire in 15 minutes.</p>
                    <p>If you didn't request this change, please secure your account immediately.</p>";

                await _emailService.SendEmailAsync(request.NewEmail, subject, body);

                // Log the activity
                var activity = new AccountActivity
                {
                    UserId = user.Id,
                    ActivityType = "Email Change Requested",
                    Description = $"Email change requested from {user.Email} to {request.NewEmail}",
                    Timestamp = DateTime.UtcNow,
                    IpAddress = _currentUserService.GetUserId() // In a real application, get the actual IP
                };

                return new ChangeEmailResponse
                {
                    Success = true,
                    Message = "Please verify your new email address with the OTP sent",
                    Otp = otp // Remove in production
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing email");
                return new ChangeEmailResponse { Success = false, Message = "An error occurred while changing email" };
            }
        }

        public async Task<UpdatePhoneNumberResponse> UpdatePhoneNumberAsync(UpdatePhoneNumberRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return new UpdatePhoneNumberResponse { Success = false, Message = "User not found" };
                }

                // Generate verification code
                var verificationCode = GenerateSecureOtp();
                user.Otp = verificationCode;
                user.OtpExpiryTime = DateTime.UtcNow.AddMinutes(15);

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return new UpdatePhoneNumberResponse { Success = false, Message = $"Failed to update phone number: {errors}" };
                }

                // In a real application, you would send SMS here
                // For now, we'll just return the code (remove in production)

                // Log the activity
                var activity = new AccountActivity
                {
                    UserId = user.Id,
                    ActivityType = "Phone Number Update Requested",
                    Description = $"Phone number update requested to {request.PhoneNumber}",
                    Timestamp = DateTime.UtcNow,
                    IpAddress = _currentUserService.GetUserId() // In a real application, get the actual IP
                };

                return new UpdatePhoneNumberResponse
                {
                    Success = true,
                    Message = "Verification code sent to your phone number",
                    VerificationCode = verificationCode // Remove in production
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating phone number");
                return new UpdatePhoneNumberResponse { Success = false, Message = "An error occurred while updating phone number" };
            }
        }

        public async Task<VerifyPhoneNumberResponse> VerifyPhoneNumberAsync(VerifyPhoneNumberRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return new VerifyPhoneNumberResponse { Success = false, Message = "User not found" };
                }

                if (user.Otp != request.VerificationCode)
                {
                    return new VerifyPhoneNumberResponse { Success = false, Message = "Invalid verification code" };
                }

                if (user.OtpExpiryTime < DateTime.UtcNow)
                {
                    return new VerifyPhoneNumberResponse { Success = false, Message = "Verification code has expired" };
                }

                // Update phone number
                user.PhoneNumber = request.PhoneNumber;
                user.PhoneNumberConfirmed = true;
                user.Otp = null;
                user.OtpExpiryTime = null;

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return new VerifyPhoneNumberResponse { Success = false, Message = $"Failed to verify phone number: {errors}" };
                }

                // Log the activity
                var activity = new AccountActivity
                {
                    UserId = user.Id,
                    ActivityType = "Phone Number Verified",
                    Description = $"Phone number {request.PhoneNumber} verified successfully",
                    Timestamp = DateTime.UtcNow,
                    IpAddress = _currentUserService.GetUserId() // In a real application, get the actual IP
                };

                return new VerifyPhoneNumberResponse { Success = true, Message = "Phone number verified successfully" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying phone number");
                return new VerifyPhoneNumberResponse { Success = false, Message = "An error occurred while verifying phone number" };
            }
        }

        public async Task<LoginHistoryResponse> GetLoginHistoryAsync()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    throw new Exception("User not found");
                }

                var loginHistory = await _context.LoginHistory
                    .Where(h => h.UserId == userId)
                    .OrderByDescending(h => h.LoginTime)
                    .Take(10) // Get last 10 logins
                    .Select(h => new LoginHistoryEntry
                    {
                        LoginTime = h.LoginTime,
                        IpAddress = h.IpAddress,
                        Device = h.Device,
                        Location = h.Location,
                        WasSuccessful = h.WasSuccessful
                    })
                    .ToListAsync();

                return new LoginHistoryResponse { LoginHistory = loginHistory };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving login history");
                throw;
            }
        }

        public async Task<AccountActivityResponse> GetAccountActivitiesAsync()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    throw new Exception("User not found");
                }

                return await _activityLoggingService.GetUserActivitiesAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving account activities");
                throw;
            }
        }

        // Replace existing TrackLoginAttempt with call to ActivityLoggingService
        private async Task TrackLoginAttempt(ApplicationUser user, bool wasSuccessful, string ipAddress, string device, string location)
        {
            await _activityLoggingService.LogLoginAttemptAsync(user.Id, wasSuccessful, ipAddress, device, location);
        }

        // Replace existing TrackAccountActivity with call to ActivityLoggingService
        private async Task TrackAccountActivity(string userId, string activityType, string description, string ipAddress)
        {
            await _activityLoggingService.LogActivityAsync(userId, activityType, description, ipAddress);
        }
    }
}
