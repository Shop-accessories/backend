using System.ComponentModel.DataAnnotations;

public class Accessory
{
    [Key]
    public int Id { get; set; }
    [Required]
    public string Name { get; set; }
    public string Description { get; set; }
    [Required]
    public decimal Price { get; set; }
    [Required]
    public string PhotoBase64 { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}