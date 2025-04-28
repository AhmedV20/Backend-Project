using System.Net;
using System.Net.Mail;

namespace DotnetAuth.Service
{
    public class SmtpEmailService : IEmailService
    {
        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUsername;
        private readonly string _smtpPassword;
        private readonly string _fromEmail;
        private readonly string _fromName;
        private readonly ILogger<SmtpEmailService> _logger;

        public SmtpEmailService(IConfiguration configuration, ILogger<SmtpEmailService> logger)
        {
            _smtpHost = configuration["Email:SmtpHost"] 
                ?? throw new ArgumentNullException("Email:SmtpHost", "SMTP host is not configured");
            _smtpPort = int.Parse(configuration["Email:SmtpPort"] 
                ?? throw new ArgumentNullException("Email:SmtpPort", "SMTP port is not configured"));
            _smtpUsername = configuration["Email:Username"] 
                ?? throw new ArgumentNullException("Email:Username", "SMTP username is not configured");
            _smtpPassword = configuration["Email:Password"] 
                ?? throw new ArgumentNullException("Email:Password", "SMTP password is not configured");
            _fromEmail = configuration["Email:FromEmail"] 
                ?? throw new ArgumentNullException("Email:FromEmail", "From Email is not configured");
            _fromName = configuration["Email:FromName"] 
                ?? throw new ArgumentNullException("Email:FromName", "From Name is not configured");
            _logger = logger;
        }

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                using var message = new MailMessage();
                message.From = new MailAddress(_fromEmail, _fromName);
                message.To.Add(new MailAddress(toEmail));
                message.Subject = subject;
                message.Body = body;
                message.IsBodyHtml = true;

                using var client = new SmtpClient(_smtpHost, _smtpPort);
                client.Credentials = new NetworkCredential(_smtpUsername, _smtpPassword);
                client.EnableSsl = true;

                await client.SendMailAsync(message);
                _logger.LogInformation("Email sent successfully to {toEmail}", toEmail);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {toEmail}", toEmail);
                return false;
            }
        }
    }
} 