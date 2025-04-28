using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DotnetAuth.Domain.Entities
{
    public class UserProfilePicture
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string FileName { get; set; }

        [Required]
        public string ContentType { get; set; }

        public string FilePath { get; set; }

        public DateTime CreatedAt { get; set; }

        public bool IsActive { get; set; }

        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }
    }

    public class UserDefaultProfilePicture
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string FileName { get; set; }

        [Required]
        public string ContentType { get; set; }

        public string FilePath { get; set; }

        public bool IsActive { get; set; }
    }
}