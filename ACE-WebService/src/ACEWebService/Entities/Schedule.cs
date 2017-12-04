using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACEWebService.Entities
{
    public class Schedule
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        public string JobName { get; set; }
        public string TriggerName { get; set; }
        public DateTime StartTime { get; set; }
        public int RepeatCount { get; set; }
        public int ExecutionCount { get; set; }
        public string ScriptId { get; set; }
    }
}
