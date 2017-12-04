using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class DiscoveryComputerListViewModel
    {
        [Required]
        public string[] ComputerName { get; set; }
        [Required]
        public Guid CredentialId { get; set; }
    }
}
