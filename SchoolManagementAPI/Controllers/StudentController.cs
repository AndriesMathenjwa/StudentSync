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
                    using (SqlCommand checkCmd = new SqlCommand("SELECT COUNT(*) FROM Parent WHERE Username=@Username OR Email=@Email", con))
                    {
                        checkCmd.Parameters.AddWithValue("@Username", student.Username);
                        checkCmd.Parameters.AddWithValue("@Email", student.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Student (IdNumber, FirstName, LastName, Email, DateOfBirth, Sex, StudentNumber, ProfilePicture, Grade, Username, Password, ParentId) VALUES (@IdNumber, @FirstName, @LastName, @Email, @DOB, @Sex, @StudentNumber, @ProfilePicture, @Grade, @Username, @Password, @ParentId)", con))
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
                        cmd.Parameters.AddWithValue("ParentId", student.ParentId);

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
                    using (SqlCommand cmd = new SqlCommand("SELECT Id, Password FROM Student WHERE Username=@Username", con))
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
                                        Username = loginModel.Username
                                    };

                                    string token = CreateToken(student);
                                    return Ok(new { message ="successful loggedin", token });
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
        private string CreateToken(Student student)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, student.Username)
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
