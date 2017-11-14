using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class CredentialViewModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
