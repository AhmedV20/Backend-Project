using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace DotnetAuth.Extensions
{
    public static class RoleInitializer
    {
        public static async Task InitializeRolesAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                string[] roles = { "Admin", "Doctor", "Patient" };

                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new IdentityRole(role));
                    }
                }

                // Initialize default profile picture
                await InitializeDefaultProfilePictureAsync(scope.ServiceProvider);
            }
        }

        private static async Task InitializeDefaultProfilePictureAsync(IServiceProvider serviceProvider)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            
            if (!await context.UserDefaultProfilePictures.AnyAsync())
            {
                var defaultPicture = new UserDefaultProfilePicture
                {
                    FileName = "default-picture-profile.png",
                    ContentType = "image/png",
                    FilePath = "/profile-pictures/defaults/default-picture-profile.png",
                    IsActive = true
                };

                await context.UserDefaultProfilePictures.AddAsync(defaultPicture);
                await context.SaveChangesAsync();
            }
        }
    }
}