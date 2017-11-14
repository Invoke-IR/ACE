using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class FileViewModel
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public byte[] Content { get; set; }
        [Required]
        public string[] Enrichment { get; set; }
        [Required]
        public string Output { get; set; }
        [Required]
        public string Language { get; set; }
    }
}
