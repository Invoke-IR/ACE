using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MyNinthMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Interval",
                table: "Schedules");

            migrationBuilder.DropColumn(
                name: "Name",
                table: "Schedules");

            migrationBuilder.AddColumn<string>(
                name: "ScriptId",
                table: "Schedules",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ScriptId",
                table: "Schedules");

            migrationBuilder.AddColumn<int>(
                name: "Interval",
                table: "Schedules",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Name",
                table: "Schedules",
                nullable: true);
        }
    }
}
