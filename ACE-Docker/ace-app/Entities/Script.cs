using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACEWebService.Entities
{
    public class Script
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public string Uri { get; set; }
        [Required]
        public string Language { get; set; }
        [Required]
        public string Enrichment { get; set; }
        [Required]
        public string Output { get; set; }
        [Required]
        public DateTime CreationTime { get; set; }
        [Required]
        public DateTime LastUpdateTime { get; set; }
    }
}