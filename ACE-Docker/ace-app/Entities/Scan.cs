using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACEWebService.Entities
{
    public class Scan
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        public string Status { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime StopTime { get; set; }
        public Guid ComputerId { get; set; }
        public virtual Computer Computer { get; set; }
        public Guid SweepIdentifier { get; set; }
    }
}