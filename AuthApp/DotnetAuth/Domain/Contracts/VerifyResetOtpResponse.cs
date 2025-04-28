namespace DotnetAuth.Domain.Contracts
{
    public class VerifyResetOtpResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ResetToken { get; set; }
    }
} 