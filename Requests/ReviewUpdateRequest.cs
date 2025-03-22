using System.ComponentModel.DataAnnotations;

public class UpdateReviewRequest
{
    [Required]
    public string Text { get; set; }
}