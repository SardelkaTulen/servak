
using Microsoft.EntityFrameworkCore;
using MyServer.Models;

namespace MyServer.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<UserAccount> Users => Set<UserAccount>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserAccount>()
            .HasIndex(user => user.NormalizedEmail)
            .IsUnique();

        modelBuilder.Entity<UserAccount>()
            .Property(user => user.Username)
            .HasMaxLength(30)
            .IsRequired();

        modelBuilder.Entity<UserAccount>()
            .Property(user => user.Email)
            .HasMaxLength(254)
            .IsRequired();

        modelBuilder.Entity<UserAccount>()
            .Property(user => user.PasswordHash)
            .IsRequired();
    }
}
