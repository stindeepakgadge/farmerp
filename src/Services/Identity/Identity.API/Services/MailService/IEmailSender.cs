using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Farmizo.Services.Identity.API.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string[] to, string[] cc, string[] bcc, string fromAddress, string fromTitle, string message, string subject);
    }
}
