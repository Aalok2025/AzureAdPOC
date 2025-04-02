using AzureAdPOC.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AzureAdPOC.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (request.Username == "user1" && request.Password == "Password@1")
            {
                var token = GenerateJwtToken(request.Username, null, "Customer"); // Generate token with username and role.
                return Ok(new { token });
            }

            return Unauthorized(); // Return 401 Unauthorized if login fails.
        }

        [HttpPost("generateToken")]
        public IActionResult GenerateToken([FromBody] TokenRequest request)
        {
            // Generate JWT token based on the provided user information.
            var token = GenerateJwtToken(request.Username, request.Email, request.Role);
            return Ok(new { token });
        }

        private string GenerateJwtToken(string username, string email, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Role, role),
                new Claim(ClaimTypes.Name, username)
            };

            if (!string.IsNullOrEmpty(email))
            {
                claims = claims.Append(new Claim(ClaimTypes.Email, email)).ToArray();
            }

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
  