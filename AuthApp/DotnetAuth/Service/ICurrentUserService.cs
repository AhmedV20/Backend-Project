namespace DotnetAuth.Service
{
    public interface ICurrentUserService
    {
        string? GetUserId();
        string? GetCurrentAccessToken();
    }
}
