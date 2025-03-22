using System.ComponentModel.DataAnnotations;

public class AccessoryCreateRequest
{
    [Required]
    public string Name { get; set; }

    public string Description { get; set; }

    [Required]
    public decimal Price { get; set; }

    [Required]
    public string PhotoBase64 { get; set; }
}
