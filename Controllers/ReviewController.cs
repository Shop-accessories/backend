using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text;

namespace Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class ReviewController : ControllerBase
    {
        private readonly MainDbContext _context;
        private string fastApiUrl = "https://bc7b-46-98-138-211.ngrok-free.app/sentiment-analysis/single";

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

            string tonality = null;

            using (var httpClient = new HttpClient())
            {
                try
                {
                    var jsonRequest = JsonSerializer.Serialize(new { review = request.Text });
                    var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");

                    var response = await httpClient.PostAsync(fastApiUrl, content);
                    if (response.IsSuccessStatusCode)
                    {
                        var jsonResponse = await response.Content.ReadAsStringAsync();
                        var result = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonResponse);
                        result.TryGetValue("tonality", out tonality);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error calling FastAPI: {ex.Message}");
                }
            }

            var review = new Review
            {
                Text = request.Text,
                UserId = user.Id,
                AccessoryId = request.AccessoryId,
                CreatedAt = DateTime.UtcNow,
                Tonality = tonality
            };

            await _context.Reviews.AddAsync(review);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Review created successfully.", Tonality = tonality });
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

            string tonality = review.Tonality;

            if (review.Text != updatedReviewRequest.Text)
            {
                using (var httpClient = new HttpClient())
                {
                    try
                    {
                        var jsonRequest = JsonSerializer.Serialize(new { review = updatedReviewRequest.Text });
                        var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");

                        var response = await httpClient.PostAsync(fastApiUrl, content);
                        if (response.IsSuccessStatusCode)
                        {
                            var jsonResponse = await response.Content.ReadAsStringAsync();
                            var result = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonResponse);
                            result.TryGetValue("tonality", out tonality);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error calling FastAPI: {ex.Message}");
                    }
                }
            }

            review.Text = updatedReviewRequest.Text;
            review.Tonality = tonality;

            _context.Reviews.Update(review);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "Review updated successfully.", Tonality = tonality });
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
