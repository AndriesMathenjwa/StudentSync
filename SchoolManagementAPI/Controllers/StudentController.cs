using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.SqlClient;
using SchoolManagementAPI.Models;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace SchoolManagementAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public StudentController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public IActionResult RegisterStudent(Student student)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("ConStr");
                using (SqlConnection con = new SqlConnection(connectionString))
                {
                    con.Open();

                    // Check if the username or email already exists
                    using (SqlCommand checkCmd = new SqlCommand("SELECT COUNT(*) FROM Student WHERE Username=@Username OR Email=@Email", con))
                    {
                        checkCmd.Parameters.AddWithValue("@Username", student.Username);
                        checkCmd.Parameters.AddWithValue("@Email", student.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    // Fetch RoleId based on RoleName
                    int roleId;
                    using (SqlCommand roleCmd = new SqlCommand("SELECT Id FROM Roles WHERE RoleName=@RoleName", con))
                    {
                        roleCmd.Parameters.AddWithValue("@RoleName", student.RoleName);
                        object result = roleCmd.ExecuteScalar();
                        if (result == null)
                        {
                            return BadRequest("Invalid role name.");
                        }
                        roleId = (int)result;
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Student (IdNumber, FirstName, LastName, Email, DateOfBirth, Sex, StudentNumber, ProfilePicture, Grade, Username, Password, ParentId, RoleId) VALUES (@IdNumber, @FirstName, @LastName, @Email, @DOB, @Sex, @StudentNumber, @ProfilePicture, @Grade, @Username, @Password, @ParentId, @RoleId)", con))
                    {
                        cmd.Parameters.AddWithValue("@IdNumber", student.IdNumber);
                        cmd.Parameters.AddWithValue("@FirstName", student.FirstName);
                        cmd.Parameters.AddWithValue("@LastName", student.LastName);
                        cmd.Parameters.AddWithValue("@Email", student.Email);
                        cmd.Parameters.AddWithValue("@DOB", student.DateOfBirth);
                        cmd.Parameters.AddWithValue("@Sex", student.Sex);
                        cmd.Parameters.AddWithValue("@StudentNumber", student.StudentNumber);
                        cmd.Parameters.AddWithValue("@ProfilePicture", student.ProfilePicture);
                        cmd.Parameters.AddWithValue("@Grade", student.Grade);
                        cmd.Parameters.AddWithValue("@Username", student.Username);
                        cmd.Parameters.AddWithValue("@Password", BCrypt.Net.BCrypt.HashPassword(student.Password));
                        cmd.Parameters.AddWithValue("@ParentId", student.ParentId);
                        cmd.Parameters.AddWithValue("@RoleId", roleId); // Use the fetched RoleId

                        int rowsAffected = cmd.ExecuteNonQuery();
                        if (rowsAffected > 0)
                        {
                            return Ok("Student registered successfully.");
                        }
                        else
                        {
                            return StatusCode(StatusCodes.Status500InternalServerError, "Error inserting data");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Error: " + ex.Message);
            }
        }

        [HttpPost("login")]
        public IActionResult LoginStudent(StudentLoginModel loginModel)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("ConStr");
                using (SqlConnection con = new SqlConnection(connectionString))
                {
                    con.Open();
                    using (SqlCommand cmd = new SqlCommand(
                        "SELECT s.Id, s.Password, r.RoleName FROM Student s " +
                        "INNER JOIN Roles r ON s.RoleId = r.Id WHERE s.Username=@Username", con))
                    {
                        cmd.Parameters.AddWithValue("@Username", loginModel.Username);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string storedHash = reader["Password"].ToString();
                                if (BCrypt.Net.BCrypt.Verify(loginModel.Password, storedHash))
                                {
                                    Student student = new Student
                                    {
                                        Id = Convert.ToInt32(reader["Id"]),
                                        Username = loginModel.Username,
                                        RoleName = reader["RoleName"].ToString()  // Fetch role name
                                    };

                                    string token = CreateToken(student);
                                    return Ok(new { message = "Successfully logged in", token });
                                }
                                else
                                {
                                    return Unauthorized("Invalid username or password");
                                }
                            }
                            else
                            {
                                return Unauthorized("Invalid username or password");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Error: " + ex.Message);
            }
        }

        [HttpGet("students")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllStudents()
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("ConStr");
                List<Student> students = new List<Student>();

                using (SqlConnection con = new SqlConnection(connectionString))
                {
                    con.Open();

                    using (SqlCommand cmd = new SqlCommand("SELECT * FROM Student", con))
                    {
                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                Student student = new Student
                                {
                                    Id = Convert.ToInt32(reader["Id"]),
                                    IdNumber = reader["IdNumber"].ToString(),
                                    FirstName = reader["FirstName"].ToString(),
                                    LastName = reader["LastName"].ToString(),
                                    Email = reader["Email"].ToString(),
                                    DateOfBirth = Convert.ToDateTime(reader["DateOfBirth"]),
                                    Sex = reader["Sex"].ToString(),
                                    StudentNumber = reader["StudentNumber"].ToString(),
                                    ProfilePicture = reader["ProfilePicture"].ToString(),
                                    Grade = reader["Grade"].ToString(),
                                    Username = reader["Username"].ToString(),
                                    Password = reader["Password"].ToString(),
                                    ParentId = Convert.ToInt32(reader["ParentId"]),
                                };

                                students.Add(student);
                            }
                        }
                    }
                }

                return Ok(students);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Error: " + ex.Message);
            }
        }
        private string CreateToken(Student student)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, student.Username),
                new Claim(ClaimTypes.Role, student.RoleName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}
