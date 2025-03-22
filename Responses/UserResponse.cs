public class UserResponseModel
{
    public int Id { get; set; }
    public string UserName { get; set; }
    public string Email { get; set; }
    public string PhoneNumber { get; set; }
    public string AvatarBase64 { get; set; }
    public DateTime CreatedAt { get; set; }
}