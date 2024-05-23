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
    public class ParentController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public ParentController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public IActionResult RegisterParent(Parent parent)
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
                        checkCmd.Parameters.AddWithValue("@Username", parent.Username);
                        checkCmd.Parameters.AddWithValue("@Email", parent.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Parents (FirstName, LastName, Email, RelationshipToStudent, ContactDetails, Address, Username, Password) VALUES (@FirstName, @LastName, @Email, @RelationshipToStudent, @ContactDetails, @Address, @Username, @Password)", con))
                    {
                        cmd.Parameters.AddWithValue("@FirstName", parent.FirstName);
                        cmd.Parameters.AddWithValue("@LastName", parent.LastName);
                        cmd.Parameters.AddWithValue("@Email", parent.Email);
                        cmd.Parameters.AddWithValue("@RelationshipToStudent", parent.RelationshipToStudent);
                        cmd.Parameters.AddWithValue("@ContactDetails", parent.ContactDetails);
                        cmd.Parameters.AddWithValue("@Address", parent.Address);
                        cmd.Parameters.AddWithValue("@Username", parent.Username);
                        cmd.Parameters.AddWithValue("@Password", BCrypt.Net.BCrypt.HashPassword(parent.Password));

                        int rowsAffected = cmd.ExecuteNonQuery();
                        if (rowsAffected > 0)
                        {
                            return Ok("Parent registered successfully.");
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
        public IActionResult LoginParent(ParentLoginModel loginModel)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("ConStr");
                using (SqlConnection con = new SqlConnection(connectionString))
                {
                    con.Open();
                    using (SqlCommand cmd = new SqlCommand("SELECT Id, Password FROM Parents WHERE Username=@Username", con))
                    {
                        cmd.Parameters.AddWithValue("@Username", loginModel.Username);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string storedHash = reader["Password"].ToString();
                                if (BCrypt.Net.BCrypt.Verify(loginModel.Password, storedHash))
                                {
                                    return Ok("Parent login successful.");
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
