using DotnetAuth.Domain.Contracts;
using Microsoft.AspNetCore.Http;

namespace DotnetAuth.Service
{
    public interface IProfilePictureService
    {
        Task<ProfilePictureResponse> UploadProfilePictureAsync(string userId, IFormFile file);
        Task<ProfilePictureResponse> GetCurrentProfilePictureAsync(string userId);
        Task<ProfilePictureHistoryResponse> GetProfilePictureHistoryAsync(string userId);
        Task<string> AssignDefaultProfilePictureAsync(string userId);
    }
}