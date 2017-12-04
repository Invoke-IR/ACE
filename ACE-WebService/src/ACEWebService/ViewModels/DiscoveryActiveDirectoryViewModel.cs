using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class DiscoveryActiveDirectoryViewModel
    {
        [Required]
        public string Domain { get; set; }
        [Required]
        public Guid CredentialId { get; set; }
    }
}