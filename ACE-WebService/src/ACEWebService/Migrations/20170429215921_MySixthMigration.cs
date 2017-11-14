using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MySixthMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Scans_Sweeps_SweepId",
                table: "Scans");

            migrationBuilder.DropIndex(
                name: "IX_Scans_SweepId",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "SweepId",
                table: "Scans");

            migrationBuilder.CreateTable(
                name: "Scripts",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    CreationTime = table.Column<DateTime>(nullable: false),
                    Language = table.Column<string>(nullable: false),
                    LastUpdateTime = table.Column<DateTime>(nullable: false),
                    Name = table.Column<string>(nullable: false),
                    Uri = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scripts", x => x.Id);
                });

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Sweeps",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Scripts");

            migrationBuilder.AddColumn<Guid>(
                name: "SweepId",
                table: "Scans",
                nullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Sweeps",
                nullable: false);

            migrationBuilder.CreateIndex(
                name: "IX_Scans_SweepId",
                table: "Scans",
                column: "SweepId");

            migrationBuilder.AddForeignKey(
                name: "FK_Scans_Sweeps_SweepId",
                table: "Scans",
                column: "SweepId",
                principalTable: "Sweeps",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
