using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;

namespace Farmizo.Services.Identity.API.Models.AccountViewModels
{
    public class OTPDetails
    {
        public int TempUserId { get; set; }

        public string PhoneNumber { get; set; }

        public string Code { get; set; }


    }
}
