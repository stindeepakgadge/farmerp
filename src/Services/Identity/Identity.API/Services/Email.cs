using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Farmizo.Services.Identity.API.Services
{
    public class Email
    {
        #region Fields

        private string[] m_emailTo;
        private string m_emailFrom;
        private string m_message;
        private string m_subject;
        private bool m_isHTML;
        private string[] m_cc;
        private string[] m_bcc;
        private SmtpClient m_client;

        #endregion

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

        #region Constructor

        public Email(string smtpHost, int smtpPort, string smtpUserName, string smtpPassword)
        {
            m_client = new SmtpClient();
            m_client.Host = smtpHost;
            m_client.Port = smtpPort;
            m_client.Credentials = new System.Net.NetworkCredential(smtpUserName, smtpPassword);
        }

        #endregion

        #region Public Methods


        public bool Send()
        {
            return Send(m_emailTo, m_cc, m_bcc, m_emailFrom, m_message, m_subject);
        }

        public bool Send(string[] to, string[] cc, string[] bcc, string from, string message, string subject)
        {
            bool isSuccess = false;
            try
            {
                ThreadPool.QueueUserWorkItem(o =>
                {
                    try
                    {
                        MailMessage mail = new MailMessage();
                        mail.IsBodyHtml = m_isHTML;

                        #region message initialization
                        if (to != null && to.Length > 0)
                        {
                            foreach (string toAddress in to)
                            {
                                mail.To.Add(toAddress);
                            }
                        }
                        if (cc != null && cc.Length > 0)
                        {
                            foreach (string ccAddress in cc)
                            {
                                mail.CC.Add(ccAddress);
                            }
                        }
                        if (bcc != null && bcc.Length > 0)
                        {
                            foreach (string bccAddress in bcc)
                            {
                                mail.Bcc.Add(bccAddress);
                            }
                        }
                        if (from != null && from.Trim().Length > 0)
                        {
                            mail.From = new MailAddress(from);
                        }
                        if (message != null && message.Trim().Length > 0)
                        {
                            mail.Body = message;
                        }
                        else
                        {
                            mail.Body = "No message specified.";
                        }
                        if (subject != null && subject.Trim().Length > 0)
                        {
                            mail.Subject = subject;
                        }
                        else
                        {
                            mail.Subject = "No subject specified.";
                        }
                        #endregion

                        // sending email
                        m_client.EnableSsl = true;
                        m_client.Send(mail);
                        isSuccess = true;
                    }
                    catch (Exception ex)
                    {
                    }
                });
            }
            catch (Exception ex)
            {
            }

            return isSuccess;
        }

        #endregion

    }
}
