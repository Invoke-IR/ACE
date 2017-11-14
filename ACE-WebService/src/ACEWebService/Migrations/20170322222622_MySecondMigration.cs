using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MySecondMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "SweepId",
                table: "Scans",
                nullable: true);

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

        protected override void Down(MigrationBuilder migrationBuilder)
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
        }
    }
}
