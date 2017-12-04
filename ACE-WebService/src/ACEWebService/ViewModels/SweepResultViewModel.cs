using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class SweepResultViewModel
    {
        [Required]
        public string ComputerName { get; set; }

        [Required]
        public string ScanType { get; set; }

        [Required]
        public string RoutingKey { get; set; }

        [Required]
        public string ResultDate { get; set; }

        [Required]
        public string ScanId { get; set; }

        [Required]
        public string[] Data { get; set; }
    }
}