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
    [Route("api/[controller]")]
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
        private async Task<User> GetUserFromToken(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                var emailClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "Email");
                if (emailClaim == null)
                    return null;

                return await _context.Users.FirstOrDefaultAsync(u => u.Email == emailClaim.Value);
            }
            catch
            {
                return null;
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
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
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
        [HttpPost("update-avatar")]
        public async Task<IActionResult> UpdateAvatar([FromHeader] string token, [FromBody] string avatarBase64)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            int maxSizeInBytes = 1000 * 1024;
            int base64Length = avatarBase64.Length;
            int dataSizeInBytes = (base64Length * 3) / 4;

            if (dataSizeInBytes > maxSizeInBytes)
                return BadRequest("Avatar size exceeds the limit of 1 MB.");

            user.AvatarBase64 = avatarBase64;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Avatar updated successfully." });
        }
        [HttpPost("update-username")]
        public async Task<IActionResult> UpdateUsername([FromHeader] string token, [FromBody] string newUsername)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            user.UserName = newUsername;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Username updated successfully." });
        }
        [HttpPost("update-email")]
        public async Task<IActionResult> UpdateEmail([FromHeader] string token, [FromBody] string newEmail)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            if (await _context.Users.AnyAsync(u => u.Email == newEmail))
                return BadRequest("A user with this email already exists.");

            user.Email = newEmail;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Email updated successfully." });
        }
        [HttpPost("update-phone-number")]
        public async Task<IActionResult> UpdatePhoneNumber([FromHeader] string token, [FromBody] string newPhoneNumber)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            if (await _context.Users.AnyAsync(u => u.PhoneNumber == newPhoneNumber))
                return BadRequest("A user with this phone number already exists.");

            user.PhoneNumber = newPhoneNumber;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Phone number updated successfully." });
        }
        [HttpGet("get-avatar")]
        public async Task<IActionResult> GetAvatar([FromHeader] string token)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            if (string.IsNullOrEmpty(user.AvatarBase64))
                return NotFound("Avatar not found.");

            return Ok(new { AvatarBase64 = user.AvatarBase64 });
        }
    }
}