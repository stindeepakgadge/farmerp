using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Farmizo.Services.Identity.API.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUserTemp
    {

        [Required]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [Phone]
        [RegularExpression(@"^([0-9]{10})$", ErrorMessage = "Please Enter Valid Mobile Number.")]
        public string PhoneNumber { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        [PasswordPropertyText]
        public string Password { get; set; }

        public string OTP { get; set; }

        public DateTime ActionDate { get; set; }

    }
}
