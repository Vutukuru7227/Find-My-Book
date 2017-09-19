namespace UsersAPI
{
    using System;
    using System.Data.Entity;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Linq;

    public partial class UsersDBContext : DbContext
    {
        public UsersDBContext()
            : base("name=UsersDBContext")
        {
        }

        public virtual DbSet<REGISTER> REGISTERs { get; set; }
        public virtual DbSet<SECURITY_QUESTIONS> SECURITY_QUESTIONS { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<REGISTER>()
                .Property(e => e.firstName)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .Property(e => e.lastName)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .Property(e => e.emailId)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .Property(e => e.password)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .Property(e => e.residence)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .Property(e => e.gender)
                .IsUnicode(false);

            modelBuilder.Entity<REGISTER>()
                .HasOptional(e => e.SECURITY_QUESTIONS)
                .WithRequired(e => e.REGISTER);

            modelBuilder.Entity<SECURITY_QUESTIONS>()
                .Property(e => e.emailId)
                .IsUnicode(false);

            modelBuilder.Entity<SECURITY_QUESTIONS>()
                .Property(e => e.question)
                .IsUnicode(false);

            modelBuilder.Entity<SECURITY_QUESTIONS>()
                .Property(e => e.answer)
                .IsUnicode(false);
        }
    }
}
