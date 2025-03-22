using System.ComponentModel.DataAnnotations;

public class Review
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string Text { get; set; }

    [Required]
    public int UserId { get; set; }

    [Required]
    public int AccessoryId { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}