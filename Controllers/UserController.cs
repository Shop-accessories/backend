using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly MainDbContext _context;

        public UserController(MainDbContext context)
        {
            _context = context;
        }

        private async Task<User> GetUserFromToken(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                var emailClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "email");
                if (emailClaim == null)
                    return null;

                return await _context.Users.FirstOrDefaultAsync(u => u.Email == emailClaim.Value);
            }
            catch
            {
                return null;
            }
        }

        [HttpGet("get-user")]
        public async Task<IActionResult> GetUser([FromHeader] string token)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token or user not found.");

            var userResponse = new UserResponseModel
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                AvatarBase64 = user.AvatarBase64,
                CreatedAt = user.CreatedAt,
            };

            return Ok(userResponse);
        }

        [HttpGet("get-username/{id}")]
        public async Task<IActionResult> GetUsernameById(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
                return NotFound("User not found.");

            return Ok(new { Username = user.UserName });
        }

        [HttpPut("update")]
        public async Task<IActionResult> UpdateUser([FromHeader] string token, [FromBody] UpdateUserRequest updatedUser)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            if (await _context.Users.AnyAsync(u => u.Email == updatedUser.Email && u.Id != user.Id))
                return BadRequest("A user with this email already exists.");

            if (await _context.Users.AnyAsync(u => u.PhoneNumber == updatedUser.PhoneNumber && u.Id != user.Id))
                return BadRequest("A user with this phone number already exists.");

            int maxSizeInBytes = 1000 * 1024;
            int base64Length = updatedUser.AvatarBase64?.Length ?? 0;
            int dataSizeInBytes = (base64Length * 3) / 4;

            if (!string.IsNullOrEmpty(updatedUser.AvatarBase64) && dataSizeInBytes > maxSizeInBytes)
                return BadRequest("Avatar size exceeds the limit of 1 MB.");

            user.UserName = updatedUser.UserName;
            user.Email = updatedUser.Email;
            user.PhoneNumber = updatedUser.PhoneNumber;
            user.AvatarBase64 = updatedUser.AvatarBase64;

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "User updated successfully." });
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> DeleteUser([FromHeader] string token)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "User deleted successfully." });
        }
    }
}
