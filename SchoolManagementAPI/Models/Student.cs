namespace SchoolManagementAPI.Models
{
    public class Student
    {
        public int Id { get; set; }
        public string? IdNumber { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string? Sex { get; set; }
        public string? StudentNumber { get; set; }
        public string? ProfilePicture { get; set; }
        public string? Grade { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public int? ParentId { get; set; }  // Ensure ParentId is an integer
    }
}
