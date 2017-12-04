using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ACEWebService.Migrations
{
    public partial class MyTwelfthMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Computers_Credentials_CredentialId",
                table: "Computers");

            migrationBuilder.DropIndex(
                name: "IX_Computers_CredentialId",
                table: "Computers");

            migrationBuilder.DropColumn(
                name: "Enrichment",
                table: "Scripts");

            migrationBuilder.AddColumn<string>(
                name: "RoutingKey",
                table: "Scripts",
                nullable: false,
                defaultValue: "");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RoutingKey",
                table: "Scripts");

            migrationBuilder.AddColumn<string>(
                name: "Enrichment",
                table: "Scripts",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_Computers_CredentialId",
                table: "Computers",
                column: "CredentialId");

            migrationBuilder.AddForeignKey(
                name: "FK_Computers_Credentials_CredentialId",
                table: "Computers",
                column: "CredentialId",
                principalTable: "Credentials",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
