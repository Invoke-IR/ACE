using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class DownloadRequestViewModel
    {
        [Required]
        public Guid ComputerId { get; set; }
        [Required]
        public string FilePath { get; set; }
        [Required]
        public string Uri { get; set; }
    }
}