using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACEWebService.Entities
{
    public class ComputerGroup
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        public string Name { get; set; }
        public Guid[] ComputerId { get; set; }
        public virtual ICollection<Computer> Computer { get; set; }
    }
}
