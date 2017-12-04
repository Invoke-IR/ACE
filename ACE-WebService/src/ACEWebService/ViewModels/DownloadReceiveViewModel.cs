using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class DownloadReceiveViewModel
    {
        [Required]
        public string ComputerName { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public string FullPath { get; set; }
        [Required]
        public byte[] Content { get; set; }
    }
}