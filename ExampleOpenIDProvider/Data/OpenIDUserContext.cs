using Microsoft.EntityFrameworkCore;

namespace ExampleOpenIDProvider.Data
{
    public class OpenIDUserContext : DbContext
    {
        public DbSet<OpenIDUser>? OpenIDUsers { get; set; }

        public OpenIDUserContext(DbContextOptions<OpenIDUserContext> options) : base(options)
        {
        }
    }
}
