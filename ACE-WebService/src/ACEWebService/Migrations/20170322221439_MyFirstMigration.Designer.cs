using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using ACEWebService.Entities;

namespace ACEWebService.Migrations
{
    [DbContext(typeof(ACEWebServiceDbContext))]
    [Migration("20170322221439_MyFirstMigration")]
    partial class MyFirstMigration
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
            modelBuilder
                .HasAnnotation("ProductVersion", "1.0.1")
                .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

            modelBuilder.Entity("ACEWebService.Entities.Computer", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("ComputerName");

                    b.Property<Guid>("CredentialId");

                    b.Property<string>("OperatingSystem");

                    b.Property<bool>("RPC");

                    b.Property<bool>("SMB");

                    b.Property<bool>("SSH");

                    b.Property<bool>("Scanned");

                    b.Property<bool>("WinRM");

                    b.HasKey("Id");

                    b.HasIndex("CredentialId");

                    b.ToTable("Computers");
                });

            modelBuilder.Entity("ACEWebService.Entities.Credential", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("Password")
                        .IsRequired();

                    b.Property<string>("UserName")
                        .IsRequired();

                    b.HasKey("Id");

                    b.ToTable("Credentials");
                });

            modelBuilder.Entity("ACEWebService.Entities.Scan", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<Guid>("ComputerId");

                    b.Property<DateTime>("StartTime");

                    b.Property<string>("Status");

                    b.Property<DateTime>("StopTime");

                    b.HasKey("Id");

                    b.HasIndex("ComputerId");

                    b.ToTable("Scans");
                });

            modelBuilder.Entity("ACEWebService.Entities.Schedule", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<int>("ExecutionCount");

                    b.Property<int>("Interval");

                    b.Property<string>("Name");

                    b.Property<DateTime>("StartTime");

                    b.HasKey("Id");

                    b.ToTable("Schedules");
                });

            modelBuilder.Entity("ACEWebService.Entities.Sweep", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<int>("CompleteCount");

                    b.Property<DateTime>("EndTime");

                    b.Property<int>("ScanCount");

                    b.Property<DateTime>("StartTime");

                    b.Property<string>("Status")
                        .IsRequired();

                    b.HasKey("Id");

                    b.ToTable("Sweeps");
                });

            modelBuilder.Entity("ACEWebService.Entities.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("ApiKey")
                        .IsRequired();

                    b.Property<string>("FirstName");

                    b.Property<bool>("IsAdmin");

                    b.Property<string>("LastName");

                    b.Property<string>("UserName")
                        .IsRequired();

                    b.HasKey("Id");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("ACEWebService.Entities.Computer", b =>
                {
                    b.HasOne("ACEWebService.Entities.Credential", "Credential")
                        .WithMany()
                        .HasForeignKey("CredentialId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("ACEWebService.Entities.Scan", b =>
                {
                    b.HasOne("ACEWebService.Entities.Computer", "Computer")
                        .WithMany()
                        .HasForeignKey("ComputerId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
        }
    }
}
