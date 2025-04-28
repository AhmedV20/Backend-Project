using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace DotnetAuth.Domain.Contracts
{
    public class UploadProfilePictureRequest
    {
        [Required]
        public IFormFile Picture { get; set; }
    }

    public class ProfilePictureResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string FileName { get; set; }
        public string FileUrl { get; set; }
        public DateTime? UploadDate { get; set; }
    }

    public class ProfilePictureHistoryResponse
    {
        public IEnumerable<ProfilePictureHistoryEntry> History { get; set; }
    }

    public class ProfilePictureHistoryEntry
    {
        public string FileName { get; set; }
        public string FileUrl { get; set; }
        public DateTime UploadDate { get; set; }
        public bool IsActive { get; set; }
    }
}