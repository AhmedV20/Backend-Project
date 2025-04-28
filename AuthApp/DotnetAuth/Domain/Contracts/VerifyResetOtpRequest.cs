using System.ComponentModel.DataAnnotations;

namespace DotnetAuth.Domain.Contracts
{
    public class VerifyResetOtpRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Otp { get; set; }
    }
} 