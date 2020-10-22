using System.ComponentModel.DataAnnotations;

namespace Farmizo.Services.Identity.API.Models.ManageViewModels
{
    public class AddPhoneNumberViewModel
    {
        [Required]
        [Phone]
        public string PhoneNumber { get; set; }
    }
}
