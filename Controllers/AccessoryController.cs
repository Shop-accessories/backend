using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AccessoryController : ControllerBase
    {
        private readonly MainDbContext _context;

        public AccessoryController(MainDbContext context)
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
                var isAdminClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "isAdmin");

                if (emailClaim == null)
                    return null;

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == emailClaim.Value);
                if (user != null && isAdminClaim != null)
                {
                    user.IsAdmin = bool.Parse(isAdminClaim.Value);
                }

                return user;
            }
            catch
            {
                return null;
            }
        }

        private async Task<bool> IsAdmin(string token)
        {
            var user = await GetUserFromToken(token);
            return user != null && user.IsAdmin;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateAccessory([FromHeader] string token, [FromBody] AccessoryCreateRequest request)
        {
            if (!await IsAdmin(token))
                return Unauthorized("Only admins can create accessories.");

            if (string.IsNullOrEmpty(request.PhotoBase64))
                return BadRequest("Photo is required in Base64 format.");

            var accessory = new Accessory
            {
                Name = request.Name,
                Description = request.Description,
                Price = request.Price,
                PhotoBase64 = request.PhotoBase64,
                CreatedAt = DateTime.UtcNow
            };

            await _context.Accessories.AddAsync(accessory);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Accessory created successfully." });
        }

        [HttpGet("all")]
        public async Task<ActionResult<IEnumerable<Accessory>>> GetAllAccessories()
        {
            return await _context.Accessories.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Accessory>> GetAccessoryById(int id)
        {
            var accessory = await _context.Accessories.FindAsync(id);
            if (accessory == null)
                return NotFound("Accessory not found.");

            return accessory;
        }

        [HttpPut("update/{id}")]
        public async Task<IActionResult> UpdateAccessory([FromHeader] string token, int id, [FromBody] AccessoryCreateRequest request)
        {
            if (!await IsAdmin(token))
                return Unauthorized("Only admins can update accessories.");

            var accessory = await _context.Accessories.FindAsync(id);
            if (accessory == null)
                return NotFound("Accessory not found.");

            accessory.Name = request.Name;
            accessory.Description = request.Description;
            accessory.Price = request.Price;
            accessory.PhotoBase64 = request.PhotoBase64;

            _context.Accessories.Update(accessory);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Accessory updated successfully." });
        }

        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteAccessory([FromHeader] string token, int id)
        {
            if (!await IsAdmin(token))
                return Unauthorized("Only admins can delete accessories.");

            var accessory = await _context.Accessories.FindAsync(id);
            if (accessory == null)
                return NotFound("Accessory not found.");

            _context.Accessories.Remove(accessory);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Accessory deleted successfully." });
        }
    }
}
