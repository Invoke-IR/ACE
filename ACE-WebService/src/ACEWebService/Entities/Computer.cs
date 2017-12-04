using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACEWebService.Entities
{
    public class Computer
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        public string ComputerName { get; set; }
        public string OperatingSystem { get; set; }
        public bool Scanned { get; set; }
        public bool SSH { get; set; }
        public bool RPC { get; set; }
        public bool SMB { get; set; }
        public bool WinRM { get; set; }
        public Guid CredentialId { get; set; }
    }
}
