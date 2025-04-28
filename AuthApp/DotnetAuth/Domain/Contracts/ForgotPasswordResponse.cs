namespace DotnetAuth.Domain.Contracts
{
    public class ForgotPasswordResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string UserId { get; set; }  // Added for activity logging
    }
}