using Microsoft.AspNetCore.Identity;

namespace DotnetAuth.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public string Role { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public string? Otp { get; set; }
        public DateTime? OtpExpiryTime { get; set; }
        public bool IsEmailConfirmed { get; set; }
    }
}
