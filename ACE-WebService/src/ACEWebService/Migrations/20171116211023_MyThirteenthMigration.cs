using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MyThirteenthMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Output",
                table: "Scripts");

            migrationBuilder.DropColumn(
                name: "AccessedTime",
                table: "Downloads");

            migrationBuilder.DropColumn(
                name: "BornTime",
                table: "Downloads");

            migrationBuilder.DropColumn(
                name: "DownloadTime",
                table: "Downloads");

            migrationBuilder.DropColumn(
                name: "ModifiedTime",
                table: "Downloads");

            migrationBuilder.AddColumn<byte[]>(
                name: "Content",
                table: "Downloads",
                nullable: false,
                defaultValue: new byte[] {  });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Content",
                table: "Downloads");

            migrationBuilder.AddColumn<string>(
                name: "Output",
                table: "Scripts",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "AccessedTime",
                table: "Downloads",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "BornTime",
                table: "Downloads",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "DownloadTime",
                table: "Downloads",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "ModifiedTime",
                table: "Downloads",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }
    }
}
