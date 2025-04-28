using Microsoft.AspNetCore.Identity;
using DotnetAuth.Domain.Contracts;

namespace DotnetAuth.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        private string _firstName;
        private string _lastName;
        
        public string FirstName 
        { 
            get => _firstName;
            set
            {
                _firstName = value;
                UpdateFullName();
            }
        }
        
        public string LastName 
        { 
            get => _lastName;
            set
            {
                _lastName = value;
                UpdateFullName();
            }
        }
        
        public string FullName { get; private set; }
        public Gender Gender { get; set; }
        public string Role { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public string? Otp { get; set; }
        public DateTime? OtpExpiryTime { get; set; }
        public bool IsEmailConfirmed { get; set; }

        // Navigation properties
        public virtual ICollection<LoginHistory> LoginHistory { get; set; }
        public virtual ICollection<AccountActivity> AccountActivities { get; set; }
        public virtual ICollection<UserProfilePicture> ProfilePictures { get; set; }

        public ApplicationUser()
        {
            LoginHistory = new List<LoginHistory>();
            AccountActivities = new List<AccountActivity>();
            ProfilePictures = new List<UserProfilePicture>();
        }

        private void UpdateFullName()
        {
            FullName = $"{_firstName} {_lastName}".Trim();
        }
    }
}
