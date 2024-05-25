namespace SchoolManagementAPI.Models
{
    public class Parent
    {
        public int Id { get; set; }
        public string? ParentIdNumber { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? RelationshipToStudent { get; set; }
        public string? ContactDetails { get; set; }
        public string? Address { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? RoleName { get; set; }
    }
}
