using System.ComponentModel.DataAnnotations;

public class ReviewCreateRequest
{
    [Required]
    public string Text { get; set; }
    [Required]
    public int AccessoryId { get; set; }
}