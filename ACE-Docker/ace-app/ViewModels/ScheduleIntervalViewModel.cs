using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class ScheduleIntervalViewModel
    {
        [Required]
        public string[] ComputerName { get; set; }
        [Required, RegularExpression("[a-zA-Z]+")]
        public string ScriptId { get; set; }
        [Required]
        public string Uri { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public int Interval { get; set; }
    }
}