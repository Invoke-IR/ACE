using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class SweepExecutionViewModel
    {
        [Required]
        public Guid[] ComputerId { get; set; }

        [Required]
        public Guid ScriptId { get; set; }

        [Required]
        public string Uri { get; set; }
    }
}