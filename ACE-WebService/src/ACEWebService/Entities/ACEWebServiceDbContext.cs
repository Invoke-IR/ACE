
using Microsoft.EntityFrameworkCore;

namespace ACEWebService.Entities
{
    public class ACEWebServiceDbContext : DbContext
    {
        public ACEWebServiceDbContext(DbContextOptions<ACEWebServiceDbContext> options) : base(options)
        {
            
        }

        public DbSet<Computer> Computers { get; set; }
        public DbSet<Credential> Credentials { get; set; }
        public DbSet<Download> Downloads { get; set; }
        public DbSet<Scan> Scans { get; set; }
        public DbSet<Schedule> Schedules { get; set; }
        public DbSet<Script> Scripts { get; set; }
        public DbSet<Sweep> Sweeps { get; set; }
        public DbSet<User> Users { get; set; }
    }
}