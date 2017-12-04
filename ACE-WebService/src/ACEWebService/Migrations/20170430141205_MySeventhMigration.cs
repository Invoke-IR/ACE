using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MySeventhMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Downloads",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    AccessedTime = table.Column<DateTime>(nullable: false),
                    BornTime = table.Column<DateTime>(nullable: false),
                    ComputerName = table.Column<string>(nullable: false),
                    DownloadTime = table.Column<DateTime>(nullable: false),
                    FullPath = table.Column<string>(nullable: false),
                    ModifiedTime = table.Column<DateTime>(nullable: false),
                    Name = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Downloads", x => x.Id);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Downloads");
        }
    }
}
