using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MimeKit;
using MailKit.Security;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using Microsoft.Extensions.Configuration;

namespace Farmizo.Services.Identity.API.Services
{
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        private string[] m_emailTo;
        private string m_emailFrom;
        private string m_emailFromTitle;
        private string m_message;
        private string m_subject;
        private bool m_isHTML;
        private string[] m_cc;
        private string[] m_bcc;

        private SmtpClient client;

        private readonly IConfiguration _configuration;


        #region Properties

        public string[] To
        {
            get { return m_emailTo; }
            set { m_emailTo = value; }
        }

        public string From
        {
            get { return m_emailFrom; }
            set { m_emailFrom = value; }
        }

        public string FromTitle
        {
            get { return m_emailFromTitle; }
            set { m_emailFromTitle = value; }
        }

        public string Message
        {
            get { return m_message; }
            set { m_message = value; }
        }

        public string Subject
        {
            get { return m_subject; }
            set { m_subject = value; }
        }

        public string[] CC
        {
            get { return m_cc; }
            set { m_cc = value; }
        }

        public string[] BCC
        {
            get { return m_bcc; }
            set { m_bcc = value; }
        }

        public bool IsHTML
        {
            get { return m_isHTML; }
            set { m_isHTML = value; }
        }

        #endregion


        public AuthMessageSender(string SmtpServer, int SmtpPortNumber, string smtpUserName, string smtpPassword)
        {
            client = new SmtpClient();
            client.Connect(SmtpServer, SmtpPortNumber, false);
            client.Authenticate(
                smtpUserName,  //Enter your email here
                smtpPassword //Enter your Password here.
                );
        }

        public AuthMessageSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        public async Task SendEmailAsync()
        {
            await SendEmailAsync(m_emailTo, m_cc, m_bcc, m_emailFrom, m_emailFromTitle, m_message, m_subject);
        }


        //string email, string subject, string message
        public async Task SendEmailAsync(string[] to, string[] cc, string[] bcc, string fromAddress, string fromTitle, string message, string subject)
        {
            try
            {

                var mimeMessage = new MimeMessage();

                #region message initialization

                if (to != null && to.Length > 0)
                {
                    foreach (string toAddress in to)
                    {
                        mimeMessage.To.Add(new MailboxAddress(toAddress));
                    }
                }
                if (cc != null && cc.Length > 0)
                {
                    foreach (string ccAddress in cc)
                    {
                        mimeMessage.Cc.Add(new MailboxAddress(ccAddress));
                    }
                }
                if (bcc != null && bcc.Length > 0)
                {
                    foreach (string bccAddress in bcc)
                    {
                        mimeMessage.Bcc.Add(new MailboxAddress(bccAddress));
                    }
                }
                if (fromAddress != null && fromAddress.Trim().Length > 0)
                {
                    mimeMessage.From.Add(new MailboxAddress
                                        (fromTitle,
                                         fromAddress
                                         ));
                }
                if (message != null && message.Trim().Length > 0)
                {
                    mimeMessage.Body = new TextPart("html")
                    {
                        Text = message
                    };
                }
                else
                {
                    mimeMessage.Body = new TextPart("html")
                    {
                        Text = "No message specified."
                    };
                }
                if (subject != null && subject.Trim().Length > 0)
                {
                    mimeMessage.Subject = subject;
                }
                else
                {
                    mimeMessage.Subject = "No subject specified.";
                }
                #endregion

                await client.SendAsync(mimeMessage);
                //Console.WriteLine("The mail has been sent successfully !!");
                //Console.ReadLine();
                await client.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }



        public Task SendSmsAsync(string recipient, string encodedMessage)
        {
            try
            {
                using (var webClient = new WebClient())
                {
                    string APIKey = _configuration.GetValue<string>("SMS_APIKey");
                    byte[] response = webClient.UploadValues("https://api.textlocal.in/send/", new NameValueCollection(){

                                         {"apikey" , APIKey},
                                         {"numbers" , recipient},
                                         {"message" , encodedMessage},
                                         {"sender" , "SHIVFE"}});

                    string result = System.Text.Encoding.UTF8.GetString(response);
                    var jsonObject = JObject.Parse(result);
                    string status = jsonObject["status"].ToString();
                }

                // Plug in your SMS service here to send a text message.

            }
            catch (Exception ex)
            {
            }

            return Task.FromResult(0);
        }
    }
}
