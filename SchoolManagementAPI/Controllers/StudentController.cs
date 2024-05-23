using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.SqlClient;
using SchoolManagementAPI.Models;
using System;

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
                    using (SqlCommand checkCmd = new SqlCommand("SELECT COUNT(*) FROM Parents WHERE Username=@Username OR Email=@Email", con))
                    {
                        checkCmd.Parameters.AddWithValue("@Username", student.Username);
                        checkCmd.Parameters.AddWithValue("@Email", student.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Students (IdNumber, FirstName, LastName, Email, DateOfBirth, Sex, StudentNumber, ProfilePicture, Grade, Username, Password) VALUES (@IdNumber, @FirstName, @LastName, @Email, @DOB, @Sex, @StudentNumber, @ProfilePicture, @Grade, @Username, @Password)", con))
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
                    using (SqlCommand cmd = new SqlCommand("SELECT Id, Password FROM Students WHERE Username=@Username", con))
                    {
                        cmd.Parameters.AddWithValue("@Username", loginModel.Username);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string storedHash = reader["Password"].ToString();
                                if (BCrypt.Net.BCrypt.Verify(loginModel.Password, storedHash))
                                {
                                    return Ok("Student login successful.");
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
    }
}
