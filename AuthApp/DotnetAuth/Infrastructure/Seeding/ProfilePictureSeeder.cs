using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DotnetAuth.Infrastructure.Seeding
{
    public class ProfilePictureSeeder
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ProfilePictureSeeder> _logger;
        private readonly IWebHostEnvironment _environment;

        public ProfilePictureSeeder(
            ApplicationDbContext context,
            ILogger<ProfilePictureSeeder> logger,
            IWebHostEnvironment environment)
        {
            _context = context;
            _logger = logger;
            _environment = environment;
        }

        public async Task SeedAsync()
        {
            try
            {
                if (!await _context.UserDefaultProfilePictures.AnyAsync())
                {
                    var defaultPicture = new UserDefaultProfilePicture
                    {
                        FileName = "default-picture-profile.png",
                        ContentType = "image/png",
                        FilePath = "/profile-pictures/defaults/default-picture-profile.png",
                        IsActive = true
                    };

                    // Ensure the default picture exists in the wwwroot folder
                    var sourcePath = Path.Combine(_environment.WebRootPath, "profile-pictures", "defaults", "default-picture-profile.png");
                    if (!File.Exists(sourcePath))
                    {
                        _logger.LogError("Default profile picture not found at {Path}", sourcePath);
                        return;
                    }

                    await _context.UserDefaultProfilePictures.AddAsync(defaultPicture);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Default profile picture seeded successfully");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error seeding default profile picture");
            }
        }
    }
}