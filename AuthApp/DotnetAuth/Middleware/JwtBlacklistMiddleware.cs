using DotnetAuth.Service;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace DotnetAuth.Middleware
{
    public class JwtBlacklistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ITokenBlacklistService _tokenBlacklistService;
        private readonly ILogger<JwtBlacklistMiddleware> _logger;

        public JwtBlacklistMiddleware(
            RequestDelegate next,
            ITokenBlacklistService tokenBlacklistService,
            ILogger<JwtBlacklistMiddleware> logger)
        {
            _next = next;
            _tokenBlacklistService = tokenBlacklistService;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            string token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (!string.IsNullOrEmpty(token))
            {
                bool isBlacklisted = await _tokenBlacklistService.IsTokenBlacklistedAsync(token);
                if (isBlacklisted)
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    await context.Response.WriteAsJsonAsync(new { message = "Token has been revoked" });
                    return;
                }
            }

            await _next(context);
        }
    }

    public static class JwtBlacklistMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtBlacklist(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtBlacklistMiddleware>();
        }
    }
}