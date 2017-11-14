using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class DownloadRequestViewModel
    {
        [Required]
        public string ComputerName { get; set; }
        [Required]
        public string FullPath { get; set; }
    }
}