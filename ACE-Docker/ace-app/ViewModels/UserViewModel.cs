using System.ComponentModel.DataAnnotations;

namespace ACEWebService.ViewModels
{
    public class UserViewModel
    {
        [Required]
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsAdmin { get; set; }
    }
}
