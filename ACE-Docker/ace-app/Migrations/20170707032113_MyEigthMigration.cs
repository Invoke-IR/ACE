using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MyEigthMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "JobName",
                table: "Schedules",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TriggerName",
                table: "Schedules",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "JobName",
                table: "Schedules");

            migrationBuilder.DropColumn(
                name: "TriggerName",
                table: "Schedules");
        }
    }
}
