using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Farmizo.Services.Identity.API.Models;
using Farmizo.Services.Identity.API.Models.AccountViewModels;
using Farmizo.Services.Identity.API.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Farmizo.Services.Identity.API.Models.ManageViewModels;
using Farmizo.Services.Identity.API.Data;
using Identity.API.Models;
using System.Web;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using System.Collections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Text.RegularExpressions;

namespace Farmizo.Services.Identity.API.Controllers
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    public class AccountController : Controller
    {

        #region --- Initialize Interface Objects ---

        //private readonly InMemoryUserLoginService _loginService;
        private readonly ILoginService<ApplicationUser> _loginService;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly ILogger<AccountController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IHostingEnvironment _hostingEnvironment;

        private readonly ApplicationDbContext _applicationDbContext;

        public AccountController(

            //InMemoryUserLoginService loginService,
            ILoginService<ApplicationUser> loginService,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            ILogger<AccountController> logger,
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            IHostingEnvironment hostingEnvironment,
            ApplicationDbContext applicationDbContext)
        {
            _loginService = loginService;
            _interaction = interaction;
            _clientStore = clientStore;
            _logger = logger;
            _userManager = userManager;
            _configuration = configuration;
            _hostingEnvironment = hostingEnvironment;
            _applicationDbContext = applicationDbContext;
        }

        #endregion

        #region --- Login ---

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                throw new NotImplementedException("External login is not implemented!");
            }

            var vm = await BuildLoginViewModelAsync(returnUrl, context);

            ViewData["ReturnUrl"] = returnUrl;

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                ApplicationUser user = new ApplicationUser();

                if (IsValidEmail(model.UserName) == true)
                {
                    user = await _loginService.FindByUsername(model.UserName);
                }
                else
                {
                    user = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == model.UserName);
                }

                if (await _loginService.ValidateCredentials(user, model.Password))
                {
                    if (user.EmailConfirmed == false)
                    {
                        return RedirectToAction("VerifyEmail", "account", new { evid = Cipher.Encrypt(user.Id, _configuration.GetValue<string>("CipherPassword")), returnUrl = model.ReturnUrl });
                    }

                    var tokenLifetime = _configuration.GetValue("TokenLifetimeMinutes", 120);

                    var props = new AuthenticationProperties
                    {
                        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(tokenLifetime),
                        AllowRefresh = true,
                        RedirectUri = model.ReturnUrl
                    };

                    if (model.RememberMe)
                    {
                        var permanentTokenLifetime = _configuration.GetValue("PermanentTokenLifetimeDays", 365);

                        props.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(permanentTokenLifetime);
                        props.IsPersistent = true;
                    };

                    await _loginService.SignInAsync(user, props);

                    // make sure the returnUrl is still valid, and if yes - redirect back to authorize endpoint
                    if (_interaction.IsValidReturnUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    return Redirect("~/");
                }

                ModelState.AddModelError("", "Invalid username or password.");
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);

            ViewData["ReturnUrl"] = model.ReturnUrl;

            return View(vm);
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl, AuthorizationRequest context)
        {
            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;
                }
            }

            return new LoginViewModel
            {
                ReturnUrl = returnUrl,
                UserName = context?.LoginHint,
                //Email = context?.LoginHint,
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginViewModel model)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl, context);
            vm.UserName = model.UserName;
            //vm.Email = model.Email;
            vm.RememberMe = model.RememberMe;
            return vm;
        }

        #endregion

        #region --- Logout ---

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            if (User.Identity.IsAuthenticated == false)
            {
                // if the user is not authenticated, then just show logged out page
                return await Logout(new LogoutViewModel { LogoutId = logoutId });
            }

            //Test for Xamarin. 
            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                //it's safe to automatically sign-out
                return await Logout(new LogoutViewModel { LogoutId = logoutId });
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            var vm = new LogoutViewModel
            {
                LogoutId = logoutId
            };
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel model)
        {
            var idp = User?.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

            if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
            {
                if (model.LogoutId == null)
                {
                    // if there's no current logout context, we need to create one
                    // this captures necessary info from the current logged in user
                    // before we signout and redirect away to the external IdP for signout
                    model.LogoutId = await _interaction.CreateLogoutContextAsync();
                }

                string url = "/Account/Logout?logoutId=" + model.LogoutId;

                try
                {
                    // hack: try/catch to handle social providers that throw
                    await HttpContext.SignOutAsync(idp, new AuthenticationProperties
                    {
                        RedirectUri = url
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "LOGOUT ERROR: {ExceptionMessage}", ex.Message);
                }
            }

            // delete authentication cookie
            await HttpContext.SignOutAsync();

            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            // set this so UI rendering sees an anonymous user
            HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(model.LogoutId);

            return Redirect(logout?.PostLogoutRedirectUri);
        }

        public async Task<IActionResult> DeviceLogOut(string redirectUrl)
        {
            // delete authentication cookie
            await HttpContext.SignOutAsync();

            // set this so UI rendering sees an anonymous user
            HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

            return Redirect(redirectUrl);
        }

        #endregion

        #region --- Register + Phone number OTP Verification  ---

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var userByEmail = await _loginService.FindByUsername(model.Email);
                var userByPhoneNumber = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == model.User.PhoneNumber);

                var validators = _userManager.PasswordValidators;
                foreach (var validator in validators)
                {
                    var result = await validator.ValidateAsync(_userManager, null, model.Password);

                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError(string.Empty, error.Description);
                        }
                    }
                }

                if (userByEmail == null && userByPhoneNumber == null && ModelState.ErrorCount == 0)
                {
                    var user = new ApplicationUserTemp
                    {
                        Email = model.Email,
                        LastName = model.User.LastName,
                        Name = model.User.Name,
                        PhoneNumber = model.User.PhoneNumber,
                        Password = Cipher.Encrypt(model.Password, _configuration.GetValue<string>("CipherPassword")),
                        ActionDate = DateTime.Now
                    };
                    _applicationDbContext.AspNetUsersTemp.Add(user);
                    await _applicationDbContext.SaveChangesAsync();

                    return RedirectToAction("Verify", "account", new { id = user.Id, returnUrl = returnUrl });
                }
                else
                {
                    if (userByEmail != null)
                    {
                        ModelState.AddModelError(string.Empty, "User name " + model.Email + " is already taken.");
                    }
                    if (userByPhoneNumber != null)
                    {
                        ModelState.AddModelError(string.Empty, "Phone number " + model.User.PhoneNumber + " is already taken.");
                    }
                    return View(model);
                }
            }

            if (returnUrl != null)
            {
                if (HttpContext.User.Identity.IsAuthenticated)
                    return Redirect(returnUrl);
                else
                    if (ModelState.IsValid)
                    return RedirectToAction("login", "account", new { returnUrl = returnUrl });
                else
                    return View(model);
            }

            return RedirectToAction("index", "home");
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult Verify(int id, string returnUrl = null)
        {
            string otp = GeneratePassword();

            ApplicationUserTemp user = _applicationDbContext.AspNetUsersTemp.Where(x => x.Id == id).OrderBy(y => y.Id).FirstOrDefault();
            user.OTP = otp;
            user.ActionDate = DateTime.Now;

            _applicationDbContext.SaveChanges();

            var objOTPDetails = new OTPDetails
            {
                TempUserId = user.Id,
                PhoneNumber = user.PhoneNumber,
                Code = "",
            };

            string recipient = objOTPDetails.PhoneNumber;           

            string message = "Your OTP For FarmERP User Registration is: " + otp;
            String encodedMessage = HttpUtility.UrlEncode(message);

            AuthMessageSender objAuthMessageSender = new AuthMessageSender(_configuration);
            objAuthMessageSender.SendSmsAsync(recipient, encodedMessage);

            ViewBag.PhoneNumber = objOTPDetails.PhoneNumber;
            ViewData["ReturnUrl"] = returnUrl;
            return View(objOTPDetails);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify(OTPDetails objOTPDetails, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            bool isVerified = false;
            if (ModelState.IsValid)
            {
                ApplicationUserTemp userTemp = _applicationDbContext.AspNetUsersTemp.Where(x => x.Id == objOTPDetails.TempUserId).OrderBy(y => y.Id).FirstOrDefault();
                if (userTemp.OTP == objOTPDetails.Code)
                {
                    var user = new ApplicationUser
                    {
                        UserName = userTemp.Email,
                        Email = userTemp.Email,
                        LastName = userTemp.LastName,
                        Name = userTemp.Name,
                        PhoneNumber = userTemp.PhoneNumber,
                        PhoneNumberConfirmed = true
                    };
                    var result = await _userManager.CreateAsync(user, Cipher.Decrypt(userTemp.Password, _configuration.GetValue<string>("CipherPassword")));
                    if (result.Errors.Count() > 0)
                    {
                        AddErrors(result);
                        // If we got this far, something failed, redisplay form
                        return View(objOTPDetails);
                    }
                    else
                    {
                        isVerified = true;

                        string confirmationToken = _userManager.GenerateEmailConfirmationTokenAsync(user).Result;
                        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
                        string confirmationLink = Url.Action("ConfirmEmail", "Account",
                            new
                            {
                                userid = user.Id,
                                token = confirmationToken,
                                client = context.ClientId,
                            },
                           protocol: HttpContext.Request.Scheme);


                        Hashtable hash = new Hashtable()
                                    {
                                        {"Name", user.Name.Trim()},
                                        {"AccountType", "New User Request"},
                                        {"ActivationLink", confirmationLink}
                                    };
                        EmailFactory mailFactory = new EmailFactory(_configuration, _hostingEnvironment);
                        AuthMessageSender objAuthMessageSender = mailFactory.SendAccountActivationMail(user.Email, hash);
                        await objAuthMessageSender.SendEmailAsync();
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "OTP verification failed. Please try again.");
                    ViewBag.PhoneNumber = objOTPDetails.PhoneNumber;
                    return View(objOTPDetails);
                }
            }

            if (returnUrl != null)
            {
                if (HttpContext.User.Identity.IsAuthenticated)
                    return Redirect(returnUrl);
                else
                    if (ModelState.IsValid && isVerified == true)
                    return RedirectToAction("RegistrationSuccess", "Account", new { returnUrl = returnUrl });
                else
                {
                    ViewBag.PhoneNumber = objOTPDetails.PhoneNumber;
                    return View(objOTPDetails);
                }
            }

            return RedirectToAction("index", "home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult RegistrationSuccess(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        #endregion

        #region --- Forgot Password ---

        [HttpGet]
        public IActionResult ForgotPassword(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordModel, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(forgotPasswordModel);

            ApplicationUser user = new ApplicationUser();

            if (IsValidEmail(forgotPasswordModel.UserName) == true)
            {
                user = await _loginService.FindByUsername(forgotPasswordModel.UserName);
            }
            else
            {
                user = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == forgotPasswordModel.UserName);
            }

            //var user = await _userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user == null)
                return RedirectToAction(nameof(ForgotPasswordConfirmation));

            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callback = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email, client = context.ClientId }, Request.Scheme);

            Hashtable hash = new Hashtable()
                                    {
                                        {"Name", user.Name.Trim()},
                                        {"AccountType", "Reset Password"},
                                        {"PasswordResetLink", callback}
                                    };
            //EmailFactory mailFactory = new EmailFactory(_configuration, _hostingEnvironment);
            //Email mail = mailFactory.SendResetPasswordMail(user.Email, hash);
            //mail.Send();

            EmailFactory mailFactory = new EmailFactory(_configuration, _hostingEnvironment);
            AuthMessageSender objAuthMessageSender = mailFactory.SendResetPasswordMail(user.Email, hash);
            await objAuthMessageSender.SendEmailAsync();


            //return RedirectToAction(nameof(ForgotPasswordConfirmation));
            return RedirectToAction("ForgotPasswordConfirmation", "account", new { returnUrl = returnUrl });
        }

        public IActionResult ForgotPasswordConfirmation(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        #endregion

        #region --- Reset Password ---

        [HttpGet]
        public IActionResult ResetPassword(string token, string email, string client)
        {
            var model = new ResetPasswordViewModel { Token = token, Email = email, Client = client };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPasswordModel, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(resetPasswordModel);
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
                RedirectToAction(nameof(ResetPasswordConfirmation));
            var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.Password);
            if (!resetPassResult.Succeeded)
            {
                foreach (var error in resetPassResult.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return View();
            }
            //return RedirectToAction(nameof(ResetPasswordConfirmation));
            return RedirectToAction("ResetPasswordConfirmation", "account", new { client = resetPasswordModel.Client });
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation(string client = null)
        {
            var clientDetails = _clientStore.FindClientByIdAsync(client);
            if (clientDetails != null)
            {
                ViewData["ReturnUrl"] = clientDetails.Result.ClientUri + "/account/signin";
            }
            return View();
        }

        #endregion        

        #region --- Password/OTP generator ---

        private string GeneratePassword()
        {
            try
            {
                bool includeLowercase = false;
                bool includeUppercase = false;
                bool includeNumeric = true;
                bool includeSpecial = false;
                bool includeSpaces = false;
                int lengthOfPassword = 6;

                string password = PasswordGenerator.GeneratePassword(includeLowercase, includeUppercase, includeNumeric, includeSpecial, includeSpaces, lengthOfPassword);

                while (!PasswordGenerator.PasswordIsValid(includeLowercase, includeUppercase, includeNumeric, includeSpecial, includeSpaces, password))
                {
                    password = PasswordGenerator.GeneratePassword(includeLowercase, includeUppercase, includeNumeric, includeSpecial, includeSpaces, lengthOfPassword);
                }

                return password;
            }
            catch (Exception ex)
            {
                ViewBag.ErrorMessage = ex.Message;
            }
            return null;
        }

        #endregion

        #region --- Email Verification ---

        [HttpGet]
        public IActionResult VerifyEmail(string evid, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["evid"] = evid;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendEmailVerificationLink(string evid, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            string decryptedId = Cipher.Decrypt(evid, _configuration.GetValue<string>("CipherPassword"));
            var user = await _userManager.FindByIdAsync(decryptedId);

            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            string confirmationToken = _userManager.GenerateEmailConfirmationTokenAsync(user).Result;
            string confirmationLink = Url.Action("ConfirmEmail", "Account",
                new
                {
                    userid = user.Id,
                    token = confirmationToken,
                    client = context.ClientId
                },
               protocol: HttpContext.Request.Scheme);

            Hashtable hash = new Hashtable()
                                    {
                                        {"Name", user.Name.Trim()},
                                        {"AccountType", "New User Request"},
                                        {"ActivationLink", confirmationLink}
                                    };
            //EmailFactory mailFactory = new EmailFactory(_configuration, _hostingEnvironment);
            //Email mail = mailFactory.SendAccountActivationMail(user.Email, hash);
            //mail.Send();

            EmailFactory mailFactory = new EmailFactory(_configuration, _hostingEnvironment);
            AuthMessageSender objAuthMessageSender = mailFactory.SendAccountActivationMail(user.Email, hash);
            await objAuthMessageSender.SendEmailAsync();

            return View();
        }

        public IActionResult ConfirmEmail(string userid, string token, string client)
        {
            var user = _userManager.FindByIdAsync(userid).Result;
            IdentityResult result = _userManager.ConfirmEmailAsync(user, token).Result;
            var clientDetails = _clientStore.FindClientByIdAsync(client);
            if (clientDetails != null)
            {
                ViewData["ReturnUrl"] = clientDetails.Result.ClientUri + "/account/signin";
            }
            if (result.Succeeded)
            {
                return View();
            }
            else
            {
                return RedirectToAction("ConfirmEmailFailed", "account");
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmEmailFailed(string returnUrl = null)
        {
            return View();
        }

        #endregion 

        #region --- Redirect ---

        [HttpGet]
        public IActionResult Redirecting()
        {
            return View();
        }

        #endregion

        #region --- ModelState Add Errors ---

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        #endregion

        #region --- Validate mail ---

        private bool IsValidEmail(string email)
        {
            return Regex.IsMatch(email, @"^[\w!#$%&'*+\-/=?\^_`{|}~]+(\.[\w!#$%&'*+\-/=?\^_`{|}~]+)*@((([\-\w]+\.)+[a-zA-Z]{2,4})|(([0-9]{1,3}\.){3}[0-9]{1,3}))\z");
        }

        #endregion
    }
}