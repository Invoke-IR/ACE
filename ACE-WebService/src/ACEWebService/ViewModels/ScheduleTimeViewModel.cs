using ACEWebService.Entities;
using System;
using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class ScheduleTimeViewModel
    {
        [Required]
        public string[] ComputerId { get; set; }
        [Required]
        public string ScriptId { get; set; }
        [Required]
        public string Uri { get; set; }
        [Required]
        public int Hour { get; set; }
        [Required]
        public int Minute { get; set; }
        [Required]
        public int Interval { get; set; }
        [Required]
        public int RepeatCount { get; set; }
    }
}