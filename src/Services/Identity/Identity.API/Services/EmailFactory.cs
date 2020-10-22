using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Farmizo.Services.Identity.API.Services
{
    public enum EmailType
    {
        AccountActivation,
        ResetPassword,
    }

    public enum Status
    {
        Approved,
        Rejected
    }

    public class EmailFactory
    {
        #region Fields

        //private Email m_email;
        private AuthMessageSender m_email;
        private string m_templateFolderPath;
        private string m_mappingFileName;


        private readonly IConfiguration _configuration;
        private readonly IHostingEnvironment _hostingEnvironment;

        #endregion Fields

        #region Properties

        #endregion Properties

        #region Constants

        private const string CONST_SUBJECT = "Subject";
        private const string CONST_FILENAME = "FileName";

        #endregion Constants

        #region Constructor

        public EmailFactory(IConfiguration configuration, IHostingEnvironment hostingEnvironment)
        {
            _configuration = configuration;
            _hostingEnvironment = hostingEnvironment;

            // reading settings from config file
            try
            {
                m_templateFolderPath = _configuration.GetValue<string>("Email_TemplateFolderPath");   //ConfigurationManager.AppSettings["EMAIL_TEMPLATE_FOLDER_PATH"];
                m_mappingFileName = _configuration.GetValue<string>("Email_MappingXMLFile");  //ConfigurationManager.AppSettings["EMAIL_MAPPING_XML_FILE"];

                m_email = new AuthMessageSender(_configuration.GetValue<string>("Email_Host"), Convert.ToInt32(_configuration.GetValue<string>("Email_Port")), _configuration.GetValue<string>("Email_UserName"), _configuration.GetValue<string>("Email_Password"));
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public EmailFactory(string smtpHost, int smtpPort, string smtpUserName, string smtpPassword)
        {
            // reading settings from config file
            try
            {
                m_templateFolderPath = _configuration.GetValue<string>("Email_TemplateFolderPath");
                m_mappingFileName = _configuration.GetValue<string>("Email_MappingXMLFile");

                m_email = new AuthMessageSender(smtpHost, smtpPort, smtpUserName, smtpPassword);

            }
            catch (Exception ex)
            {
                throw;
            }
        }

        #endregion Constructor

        #region Public Methods

        public AuthMessageSender GetMail()
        {
            return m_email;
        }

        public AuthMessageSender SendAccountActivationMail(string to, Hashtable hashTemplateVars)
        {
            try
            {
                m_email.To = new string[] { to };
                m_email.From = _configuration.GetValue<string>("Email_UserName");
                m_email.FromTitle = _configuration.GetValue<string>("Email_UserNameTitle");
                ConstructMail(EmailType.AccountActivation);
                m_email.Message = m_email.Message.Replace("#Name#", hashTemplateVars["Name"].ToString());
                m_email.Message = m_email.Message.Replace("#ActivationLink#", hashTemplateVars["ActivationLink"].ToString());
                m_email.IsHTML = true;

            }
            catch (Exception ex)
            {
                throw;
            }

            return m_email;
        }

        public AuthMessageSender SendResetPasswordMail(string to, Hashtable hashTemplateVars)
        {
            try
            {
                m_email.To = new string[] { to };
                m_email.From = _configuration.GetValue<string>("Email_UserName");
                m_email.FromTitle = _configuration.GetValue<string>("Email_UserNameTitle");
                ConstructMail(EmailType.ResetPassword);
                m_email.Message = m_email.Message.Replace("#Name#", hashTemplateVars["Name"].ToString());
                m_email.Message = m_email.Message.Replace("#PasswordResetLink#", hashTemplateVars["PasswordResetLink"].ToString());
                m_email.IsHTML = true;

            }
            catch (Exception ex)
            {
                throw;
            }

            return m_email;
        }


        #endregion Public Methods

        #region private Methods

        private void ConstructMail(EmailType emailType)
        {
            string emailMappingFile = string.Empty;
            string templateFile = string.Empty;
            StreamReader reader = null;
            try
            {
                emailMappingFile = _hostingEnvironment.ContentRootPath + Path.Combine(m_templateFolderPath, m_mappingFileName);

                // reading the xml file into XmlDocument object
                XmlDocument xml = new XmlDocument();
                xml.LoadXml(File.ReadAllText(emailMappingFile));

                // getting mail subject and mail template file name
                m_email.Subject = xml.SelectSingleNode("//" + emailType.ToString() + "/" + CONST_SUBJECT).FirstChild.Value;
                templateFile = xml.SelectSingleNode("//" + emailType.ToString() + "/" + CONST_FILENAME).FirstChild.Value;
                templateFile = _hostingEnvironment.ContentRootPath + Path.Combine(m_templateFolderPath, templateFile);

                reader = new StreamReader(templateFile);
                m_email.Message = reader.ReadToEnd();
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
        }

        #endregion private Methods
    }
}
