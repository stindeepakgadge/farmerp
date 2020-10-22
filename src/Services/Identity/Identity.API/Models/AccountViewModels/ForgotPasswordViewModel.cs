using System.ComponentModel.DataAnnotations;

namespace Farmizo.Services.Identity.API.Models.AccountViewModels
{
    public class ForgotPasswordViewModel
    {
        //[Required]
        //[EmailAddress]
        //public string Email { get; set; }

        [Required]
        public string UserName { get; set; }
    }
}
