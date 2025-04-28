/*

using SendGrid;
using SendGrid.Helpers.Mail;

namespace DotnetAuth.Service
{
    public class SendGridEmailService : IEmailService
    {
        private readonly string _apiKey;
        private readonly string _fromEmail;
        private readonly string _fromName;
        private readonly ILogger<SendGridEmailService> _logger;

        public SendGridEmailService(IConfiguration configuration, ILogger<SendGridEmailService> logger)
        {
            _apiKey = configuration["SendGrid:ApiKey"] 
                ?? throw new ArgumentNullException("SendGrid:ApiKey", "SendGrid API key is not configured");
            _fromEmail = configuration["SendGrid:FromEmail"] 
                ?? throw new ArgumentNullException("SendGrid:FromEmail", "SendGrid From Email is not configured");
            _fromName = configuration["SendGrid:FromName"] 
                ?? throw new ArgumentNullException("SendGrid:FromName", "SendGrid From Name is not configured");
            _logger = logger;
        }

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                var client = new SendGridClient(_apiKey);
                var from = new EmailAddress(_fromEmail, _fromName);
                var to = new EmailAddress(toEmail);
                var msg = MailHelper.CreateSingleEmail(from, to, subject, body, body);
                
                var response = await client.SendEmailAsync(msg);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Email sent successfully to {toEmail}", toEmail);
                    return true;
                }
                
                _logger.LogError("Failed to send email to {toEmail}. Status code: {statusCode}", 
                    toEmail, response.StatusCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {toEmail}", toEmail);
                return false;
            }
        }
    }
} 

*/