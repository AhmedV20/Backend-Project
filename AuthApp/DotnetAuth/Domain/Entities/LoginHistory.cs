namespace DotnetAuth.Domain.Entities
{
    public class LoginHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTime LoginTime { get; set; }
        public string IpAddress { get; set; }
        public string Device { get; set; }
        public string Location { get; set; }
        public bool WasSuccessful { get; set; }
        public virtual ApplicationUser User { get; set; }
    }

    public class AccountActivity
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTime Timestamp { get; set; }
        public string ActivityType { get; set; }
        public string Description { get; set; }
        public string IpAddress { get; set; }
        public virtual ApplicationUser User { get; set; }
    }
}