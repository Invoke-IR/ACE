using System;
using System.Collections;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class ArbitrarySweepViewModel
    {
        [Required]
        public Hashtable Arguments { get; set; }
        [Required]
        public Guid[] ComputerId { get; set; }
        [Required]
        public string Script { get; set; }
        [Required]
        public string Uri { get; set; }
    }
}