using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Controllers
{
    [Route("Auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly MainDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(MainDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterRequest request)
        {
            return await Register(request, false);
        }

        [HttpPost("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterRequest request, [FromHeader] string? adminToken)
        {
            if (string.IsNullOrEmpty(adminToken) || !IsAdmin(adminToken))
                return Unauthorized("Only admins can create other admins.");

            return await Register(request, true);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);
            if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
                return Unauthorized("Invalid username or password.");

            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        private async Task<IActionResult> Register(RegisterRequest request, bool isAdmin)
        {
            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                return BadRequest("A user with this email already exists.");

            if (await _context.Users.AnyAsync(u => u.PhoneNumber == request.PhoneNumber))
                return BadRequest("This phone number is already in use.");

            var passwordHash = HashPassword(request.Password);

            var user = new User
            {
                UserName = request.UserName,
                Email = request.Email,
                PasswordHash = passwordHash,
                PhoneNumber = request.PhoneNumber,
                IsAdmin = isAdmin,
                CreatedAt = DateTime.UtcNow,
                AvatarBase64 = ""
            };

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = isAdmin ? "Admin registered successfully." : "User registered successfully." });
        }

        private bool IsAdmin(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);
                var adminClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "isAdmin");
                return adminClaim != null && adminClaim.Value == "true";
            }
            catch
            {
                return false;
            }
        }

        private string HashPassword(string password)
        {
            var salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return $"{Convert.ToBase64String(salt)}:{hashed}";
        }

        private bool VerifyPassword(string enteredPassword, string storedPasswordHash)
        {
            var parts = storedPasswordHash.Split(':');
            var salt = Convert.FromBase64String(parts[0]);
            var hash = parts[1];

            var enteredHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: enteredPassword,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return hash == enteredHash;
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim("userName", user.UserName),
                new Claim("email", user.Email),
                new Claim("isAdmin", user.IsAdmin.ToString().ToLower())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
