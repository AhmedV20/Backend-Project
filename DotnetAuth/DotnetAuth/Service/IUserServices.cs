using DotnetAuth.Domain.Contracts;
namespace DotnetAuth.Service
{
    public interface IUserServices
    {
        Task<UserRegisterResponse> RegisterAsync(UserRegisterRequest request);
        Task<UserResponse> LoginAsync(UserLoginRequest request);
        Task<CurrentUserResponse> GetCurrentUserAsync();
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest);
        Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request);
        Task<VerifyOtpResponse> VerifyOtpAsync(VerifyOtpRequest request);
        Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordRequest request);
        Task<VerifyResetOtpResponse> VerifyResetOtpAsync(VerifyResetOtpRequest request);
        Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordRequest request);
    }
}
