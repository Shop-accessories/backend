using Microsoft.EntityFrameworkCore;

public class MainDbContext : DbContext
{
    public MainDbContext(DbContextOptions<MainDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<Accessory> Accessories { get; set; }
    public DbSet<Review> Reviews { get; set; }
}