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
                    using (SqlCommand checkCmd = new SqlCommand("SELECT COUNT(*) FROM Parent WHERE Username=@Username OR Email=@Email", con))
                    {
                        checkCmd.Parameters.AddWithValue("@Username", parent.Username);
                        checkCmd.Parameters.AddWithValue("@Email", parent.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Parent (ParentIdNumber, FirstName, LastName, Email, RelationshipToStudent, ContactDetails, Address, Username, Password) VALUES (@ParentIdNumber, @FirstName, @LastName, @Email, @RelationshipToStudent, @ContactDetails, @Address, @Username, @Password)", con))
                    {
                        cmd.Parameters.AddWithValue("@ParentIdNumber", parent.ParentIdNumber);
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
                    using (SqlCommand cmd = new SqlCommand("SELECT Id, Password FROM Parent WHERE Username=@Username", con))
                    {
                        cmd.Parameters.AddWithValue("@Username", loginModel.Username);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string storedHash = reader["Password"].ToString();
                                if (BCrypt.Net.BCrypt.Verify(loginModel.Password, storedHash))
                                {
                                    Parent parent = new Parent
                                    {
                                        Id = Convert.ToInt32(reader["Id"]),
                                        Username = loginModel.Username
                                    };
                                    string token = CreateToken(parent);
                                    return Ok(new { message = "successful loggedin", token });
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

        private string CreateToken(Parent parent)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, parent.Username)
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