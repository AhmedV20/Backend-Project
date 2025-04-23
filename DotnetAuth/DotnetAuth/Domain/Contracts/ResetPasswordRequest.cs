using System.ComponentModel.DataAnnotations;

namespace DotnetAuth.Domain.Contracts
{
    public class ResetPasswordRequest
    {
        [Required]
        [MinLength(6)]
        public string NewPassword { get; set; }

        [Required]
        [Compare("NewPassword")]
        public string ConfirmPassword { get; set; }
    }
} 