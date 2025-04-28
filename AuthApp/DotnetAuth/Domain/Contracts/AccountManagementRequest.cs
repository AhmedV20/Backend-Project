using System.ComponentModel.DataAnnotations;

namespace DotnetAuth.Domain.Contracts
{
    public class ChangeEmailRequest
    {
        [Required]
        [EmailAddress]
        public string NewEmail { get; set; }

        [Required]
        public string Password { get; set; }
    }

    public class ChangeEmailResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string? Otp { get; set; }
    }

    public class UpdatePhoneNumberRequest
    {
        [Required]
        [Phone]
        public string PhoneNumber { get; set; }
    }

    public class UpdatePhoneNumberResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string? VerificationCode { get; set; }
    }

    public class VerifyPhoneNumberRequest
    {
        [Required]
        [Phone]
        public string PhoneNumber { get; set; }

        [Required]
        public string VerificationCode { get; set; }
    }

    public class VerifyPhoneNumberResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }

    public class LoginHistoryResponse
    {
        public IEnumerable<LoginHistoryEntry> LoginHistory { get; set; }
    }

    public class LoginHistoryEntry
    {
        public DateTime LoginTime { get; set; }
        public string IpAddress { get; set; }
        public string Device { get; set; }
        public string Location { get; set; }
        public bool WasSuccessful { get; set; }
    }

    public class AccountActivityResponse
    {
        public IEnumerable<AccountActivityEntry> Activities { get; set; }
    }

    public class AccountActivityEntry
    {
        public DateTime Timestamp { get; set; }
        public string ActivityType { get; set; }
        public string Description { get; set; }
        public string IpAddress { get; set; }
    }
}