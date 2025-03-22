using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class ReviewController : ControllerBase
    {
        private readonly MainDbContext _context;

        public ReviewController(MainDbContext context)
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
        public async Task<IActionResult> CreateReview([FromHeader] string token, [FromBody] ReviewCreateRequest request)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            var review = new Review
            {
                Text = request.Text,
                UserId = user.Id,
                AccessoryId = request.AccessoryId,
                CreatedAt = DateTime.UtcNow
            };

            await _context.Reviews.AddAsync(review);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Review created successfully." });
        }

        [HttpGet("all")]
        public async Task<ActionResult<IEnumerable<Review>>> GetAllReviews([FromHeader] string token)
        {
            if (!await IsAdmin(token))
                return Unauthorized("Only admins can view all reviews.");

            return await _context.Reviews.ToListAsync();
        }

        [HttpGet("my")]
        public async Task<ActionResult<IEnumerable<Review>>> GetMyReviews([FromHeader] string token)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            return await _context.Reviews.Where(r => r.UserId == user.Id).ToListAsync();
        }

        [HttpPut("update/{id}")]
        public async Task<IActionResult> UpdateReview([FromHeader] string token, int id, [FromBody] UpdateReviewRequest updatedReviewRequest)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            var review = await _context.Reviews.FindAsync(id);
            if (review == null)
                return NotFound("Review not found.");

            if (review.UserId != user.Id && !user.IsAdmin)
                return Forbid("You can only update your own reviews.");

            review.Text = updatedReviewRequest.Text;

            _context.Reviews.Update(review);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Review updated successfully." });
        }

        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteReview([FromHeader] string token, int id)
        {
            var user = await GetUserFromToken(token);
            if (user == null)
                return Unauthorized("Invalid token.");

            var review = await _context.Reviews.FindAsync(id);
            if (review == null)
                return NotFound("Review not found.");

            if (review.UserId != user.Id && !user.IsAdmin)
                return Forbid("You can only delete your own reviews.");

            _context.Reviews.Remove(review);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Review deleted successfully." });
        }
    }
}
