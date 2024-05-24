using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using SchoolManagementAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SchoolManagementAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AdminController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public IActionResult RegisterAdmin(Admin admin)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("ConStr");
                using (SqlConnection con = new SqlConnection(connectionString))
                {
                    con.Open();

                    using (SqlCommand checkCmd = new SqlCommand("SELECT COUNT(*) FROM Admin WHERE Username=@Username OR Email=@Email", con))
                    {
                        checkCmd.Parameters.AddWithValue("@Username", admin.Username);
                        checkCmd.Parameters.AddWithValue("@Email", admin.Email);

                        int userCount = (int)checkCmd.ExecuteScalar();
                        if (userCount > 0)
                        {
                            return Conflict("Username or email already exists.");
                        }
                    }

                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Admin (FirstName, LastName, Email, ContactDetails, Username, Password) VALUES ( @FirstName, @LastName, @Email, @ContactDetails, @Username, @Password)", con))
                    {
                        cmd.Parameters.AddWithValue("@FirstName", admin.FirstName);
                        cmd.Parameters.AddWithValue("@LastName", admin.LastName);
                        cmd.Parameters.AddWithValue("@Email", admin.Email);
                        cmd.Parameters.AddWithValue("@ContactDetails", admin.ContactDetails);
                        cmd.Parameters.AddWithValue("@Username", admin.Username);
                        cmd.Parameters.AddWithValue("@Password", BCrypt.Net.BCrypt.HashPassword(admin.Password));

                        int rowsAffected = cmd.ExecuteNonQuery();
                        if (rowsAffected > 0)
                        {
                            return Ok("Admin registered successfully.");
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
                    using (SqlCommand cmd = new SqlCommand("SELECT Id, Password FROM Admin WHERE Username=@Username", con))
                    {
                        cmd.Parameters.AddWithValue("@Username", loginModel.Username);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string storedHash = reader["Password"].ToString();
                                if (BCrypt.Net.BCrypt.Verify(loginModel.Password, storedHash))
                                {
                                    Admin admin = new Admin
                                    {
                                        Id = Convert.ToInt32(reader["Id"]),
                                        Username = loginModel.Username
                                    };
                                    string token = CreateToken(admin);
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

        private string CreateToken(Admin admin)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, admin.Username)
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
