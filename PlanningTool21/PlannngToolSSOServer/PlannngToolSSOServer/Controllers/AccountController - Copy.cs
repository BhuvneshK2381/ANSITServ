using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NorthStarHubSSO.Models;
using NorthStarHubSSO.Models.AccountViewModels;
using NorthStarHubSSO.Services;
using IdentityServer4.Quickstart.UI;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using NorthStarHub.DBL.Models.UserManagement;
using Newtonsoft.Json;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Http;
using NorthStarHub.Constants;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using NorthStarHub.Utilities.MailRepository;
using System.Net.Mail;
using NorthStarHub.AppSettings.Constants;
using NorthStarHub.AppSettings.Repository;
using NorthStarHub.DBL;
using System.Net.Http.Json;

namespace NorthStarHubSSO.Controllers
{

    public class Appointment
    {
       
        public string Guid { get; set; }
        public string reasonForVisit { get; set; }
        public string reasonOfVisitOther { get; set; }
        public string patientID { get; set; }
        public string otherResion { get; set; }
        public string insuranceType { get; set; }
        public string insurancePlanID { get; set; }
        public string appointmentUrgencyID { get; set; }
        public string doctorAvailabilityID { get; set; }
        public string doctorID { get; set; }
        public string doctorLocationID { get; set; }              
        public List<string> doctorVisitReasonID { get; set; }
        public string BodyPartsID { get; set; }
        public bool IsFacility { get; set; }
        public DateTime withoutSlotRequestedDateTime { get; set; }
        public string userId { get; set; }
    }

    public class Res
    {
        public bool Success { get; set; }
        public string Data { get; set; }
    }

    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        const string SessionName = "_UserID";
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private readonly NorthStarHubDBContext _dBContext;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly AccountService _account;
        private readonly IWebHostEnvironment _environment;
        public static List<Appointment> Appointments { get; set; } = new List<Appointment>();
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider, IWebHostEnvironment environment, NorthStarHubDBContext dbContext
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
            _environment = environment;
            _dBContext = dbContext;
            _interaction = interaction;
            _account = new AccountService(interaction, httpContextAccessor, schemeProvider, clientStore);
        }

        [TempData]
        public string ErrorMessage { get; set; }

        [HttpPost]
        [AllowAnonymous]
        public Res AppointmentData([FromBody]Appointment appointment)
        {

            appointment.Guid = Convert.ToString(Guid.NewGuid());
            Appointments.Add(appointment);
            var res = new Res()
            {
                Success = true,
                Data = appointment.Guid
            };
            return res;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null, bool IsPasswordReset = false, string email=null)
        
        {   
            //Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme); 
            if(!string.IsNullOrEmpty(email))
            {
                 await GenratePassword(email);
            }
            ViewData["ReturnUrl"] = returnUrl;
            ViewBag.ResetPass = IsPasswordReset;
            return View();
        }


        /// <summary>
        /// Genrate Password for new invited users
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        private async Task<bool> GenratePassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ViewBag.NewProvider = "You are not exist in NorthStarDoc System";
                return false;
            }
            if (!user.IsNewUsers)
            {
                return false;
            }
            var roles = await _userManager.GetRolesAsync(user);
            string name = string.Empty;
            if(roles.Count==1)
            {
                string role = roles[0];
                if (role == "Doctor")
                {
                    var doc = _dBContext.Doctors.FirstOrDefault(x => x.UserID == user.Id);
                    doc.RecordStatus = RecordStatusConstants.Active;
                    name = doc.Name ?? "";
                    var invitedUser = _dBContext.UserInvitations.Where(x => x.Email == user.Email && x.Type.ToUpper() == UserRoleConstant.Doctor && x.InvitationStatus == "Waiting").FirstOrDefault();
                    invitedUser.InvitationStatus = ReferralStatusConstant.Accepted;
                }
                else
                {
                    var fac = _dBContext.Facilities.FirstOrDefault(x => x.UserID == user.Id);
                    fac.RecordStatus = RecordStatusConstants.Active;
                    name = fac.FacilityName ?? "";

                    var invitedUser = _dBContext.UserInvitations.Where(x => x.Email == user.Email && x.Type.ToUpper() == UserRoleConstant.Facility && x.InvitationStatus == "Waiting").FirstOrDefault();
                    invitedUser.InvitationStatus = ReferralStatusConstant.Accepted;

                }
            }
            var password = "@aB0" + CreateRandomPassword(8);
            // For more information on how to enable account confirmation and password reset please
            // visit https://go.microsoft.com/fwlink/?LinkID=532713
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _userManager.ResetPasswordAsync(user, code, password);
            
            string mailTo = user.Email;
            string strSubject = "NorthStarHub: New User Registered";
            string Tempbody = "";
            var fileProvider = _environment.WebRootFileProvider;

            // here you define only subpath

            var fileInfo = fileProvider.GetFileInfo("/EmailTemplates/LoginCredentialForNewUser.html");
            var fileStream = fileInfo.CreateReadStream();
            using (var reader = new StreamReader(fileStream))
            {
                Tempbody = reader.ReadToEnd();
            }
            string strBody = String.Format(Tempbody, name, user.Email, password);

            //  send Mail
            var res = await SendMailWithoutAttachment("", "", mailTo, strSubject, strBody);
            if (res)
            {
                ViewBag.NewProvider = "Your credentials sent on you email.Please check your email.";
                user.IsNewUsers = false;
                await _dBContext.SaveChangesAsync();
            }
            else
                ViewBag.NewProvider = "something went wrong.";
            return res;
        }

        [HttpPost]
        [AllowAnonymous]
      
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
    
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
             
                ApplicationUser user = new ApplicationUser();
                //var user = await _userManager.FindByNameAsync(model.Username);
                if (model.Username.Contains("@") && model.Username.Contains("."))
                {
                   
                    user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.Email.ToLower() == model.Username.ToLower() && x.IsUserActive).FirstOrDefault();
                    if (model.IsMultiAccount)
                    {
                        user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.Email.ToLower() == model.Username.ToLower() && x.Patient.DateOfBirth == model.DateOfBirth && x.IsUserActive).FirstOrDefault();
                    }
                }
                else
                {
                    user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.PhoneNumber == model.Username && x.IsUserActive).FirstOrDefault();
                    if (model.IsMultiAccount)
                    {
                        user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.PhoneNumber == model.Username && x.Patient.DateOfBirth == model.DateOfBirth && x.IsUserActive).FirstOrDefault();
                    }
                }



                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }


                var role = await _userManager.GetRolesAsync(user);
              
                if (role.Count == 1 && role.Contains("Patient"))
                {
                    var ChildPatient = _dBContext.Patients.Where(x => x.UserID == user.Id).FirstOrDefault();
                    if(ChildPatient != null && ChildPatient.IsChildPatient ==true && ChildPatient.RecordStatus == RecordStatusConstants.Active)
                    {
                        ModelState.AddModelError(string.Empty, "You are registered as minor patient please use your parent account.");
                        return View(model);
                    }
                   
                }
                HttpContext.Session.SetString(SessionName, user.Id);
                var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {                     
                    bool success = false;
                    if (user!=null)
                    {
                        int indexOfGuid = returnUrl.IndexOf("Guid");
                        if (indexOfGuid > 0)
                        {
                            string removefromUrl = returnUrl.Substring(indexOfGuid);
                            string guid = returnUrl.Substring(indexOfGuid + 5);
                            returnUrl = returnUrl.Replace(removefromUrl, "");
                            if (Appointments.Count > 0)
                            {            
                                var data = Appointments.Where(x => x.Guid == guid).FirstOrDefault();
                                if(data!=null)
                                {
                                    data.userId = user.Id;
                                    var req = new
                                    {
                                        data.doctorID,
                                        data.userId,
                                        data.insurancePlanID,
                                        data.reasonOfVisitOther,
                                        data.doctorAvailabilityID,
                                        data.withoutSlotRequestedDateTime,
                                        data.appointmentUrgencyID,
                                        data.doctorLocationID,
                                        data.IsFacility,
                                        data.BodyPartsID,
                                        doctorVisitReasonID = string.Join(",", data.doctorVisitReasonID ?? new List<string>()),
                                        data.insuranceType
                                    };
                                    success= await AddAppointment(req);
                                    if (success)
                                    {
                                      
                                        Appointments.Remove(data);
                                    }
                                }
                            }
                        }
                    }

                   
                    if (role.Count==1)
                    {
                        switch (role[0])
                        {
                            case "Doctor":
                                if (returnUrl.Contains("localhost"))
                                {
                                    returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.doctorLocalRedirectUri);
                                }
                                else
                                {
                                  
                                    returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.doctorRedirectUri);
                                }
                                break;
                            case "DoctorStaff":
                                if (returnUrl.Contains("localhost"))
                                {
                                    var MultipleStaff = _dBContext.DoctorStaffs.Where(x => x.UserID == user.Id && x.RecordStatus == RecordStatusConstants.Active).ToList();
                                    if (MultipleStaff != null && MultipleStaff.Count() > 1)
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.staffRolemanagrRedirectUri);
                                    }
                                    else
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.doctorStaffLocalRedirectUri);
                                    }
                                   
                                }
                                else
                                {
                                    var MultipleStaff = _dBContext.DoctorStaffs.Where(x => x.UserID == user.Id && x.RecordStatus == RecordStatusConstants.Active).ToList();
                                    if (MultipleStaff != null && MultipleStaff.Count() > 1)
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.staffRolemanagrRedirectUri);
                                    }
                                    else
                                    {
                                      
                                        returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.doctorStaffRedirectUri);
                                    }
                                    
                                }
                                break;
                            case "Patient":

                                if (returnUrl.Contains("localhost"))
                                {
                                    returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, success ? Config.patientLocalRedirectUri + "appointment/" : Config.patientLocalRedirectUri);
                                }
                                else
                                {
                                    returnUrl = returnUrl.Replace(Config.loginRedirectUri, success ? Config.patientRedirectUri + "appointment/" : Config.patientRedirectUri);
                                }
                                break;
                            case "Facility":
                                if (returnUrl.Contains("localhost"))
                                {
                                    returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.facilityLocalRedirectUri);
                                }
                                else
                                {
                                 
                                    returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.facilityRedirectUri);
                                }
                                break;
                            case "FacilityStaff":
                                if (returnUrl.Contains("localhost"))
                                {
                                    var MultipleStaff = _dBContext.FacilityStaffs.Where(x => x.UserID == user.Id && x.RecordStatus == RecordStatusConstants.Active).ToList();
                                    if (MultipleStaff != null && MultipleStaff.Count() > 1)
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.staffRolemanagrRedirectUri);
                                    }
                                    else
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.facilityStaffLocalRedirectUri);
                                    }
                                   
                                }
                                else
                                {
                                    var MultipleStaff = _dBContext.FacilityStaffs.Where(x => x.UserID == user.Id && x.RecordStatus == RecordStatusConstants.Active).ToList();
                                    if (MultipleStaff != null && MultipleStaff.Count() > 1)
                                    {
                                        returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.staffRolemanagrRedirectUri);
                                    }
                                    else
                                    {
                                        
                                        returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.facilityStaffRedirectUri);
                                    }
                                    
                                } 
                                break;
                            default: break;
                        }
                    }
                    else
                    {
                        if (returnUrl.Contains("localhost"))
                        {
                            returnUrl = returnUrl.Replace(Config.loginLocalRedirectUri, Config.staffRolemanagrRedirectUri);
                        }
                        else
                        {
                            returnUrl = returnUrl.Replace(Config.loginRedirectUri, Config.staffRolemanagrRedirectUri);
                        }
                    }     
                    _logger.LogInformation("User logged in.");
                      return RedirectToLocal(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToAction(nameof(Lockout));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var model = new LoginWith2faViewModel { RememberMe = rememberMe };
            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return View();
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return View();
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

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
        public async Task<IActionResult> Register(RegisterViewModel model, string role, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, role);
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User created a new account with password.");
                    return RedirectToLocal(returnUrl);
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await _account.BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await _account.BuildLoggedOutViewModelAsync(model.LogoutId);

            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                // hack: try/catch to handle social providers that throw
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToAction(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["LoginProvider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(nameof(ExternalLogin), model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword(string returnUrl =null, bool IsPasswordReset = false)
        {
            ViewData["ReturnUrl"] = returnUrl;
            ViewBag.ResetPass1 = IsPasswordReset;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model,string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return /*RedirectToAction(nameof(ForgotPasswordConfirmation));*/ RedirectToAction(nameof(ForgotPassword), new { returnUrl = returnUrl, IsPasswordReset = true });
                }
                var password = "@aB0" + CreateRandomPassword(8);
                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var UserName = string.Empty;
                var result = await _userManager.ResetPasswordAsync(user,code, password);
                var roles = await _userManager.GetRolesAsync(user);
                if(roles.Count() == 1)
                {
                    if(roles.Contains("Doctor"))
                    {
                        var doctor = _dBContext.Doctors.Where(x => x.UserID == user.Id).FirstOrDefault();
                        UserName = doctor.FirstName + doctor.LastName;
                    }
                    else if (roles.Contains("Facility"))
                    {
                        var facility = _dBContext.Facilities.Where(x => x.UserID == user.Id).FirstOrDefault();
                        UserName = facility.FacilityName;
                    }
                    else if (roles.Contains("Patient"))
                    {
                        var patient = _dBContext.Patients.Where(x => x.UserID == user.Id).FirstOrDefault();
                        UserName = patient.FirstName +" "+ patient.LastName;
                    }
                    else if (roles.Contains("FacilityStaff"))
                    {
                        var staffList = _dBContext.FacilityStaffs.Where(x => x.UserID == user.Id).ToList();
                        foreach (var item in staffList)
                        {
                            UserName += item.FirstName + " " + item.LastName+",";
                        }
                        UserName = UserName.TrimEnd(',');
                    }
                    else if (roles.Contains("DoctorStaff"))
                    {
                        var staffList1 = _dBContext.DoctorStaffs.Where(x => x.UserID == user.Id).ToList();
                        foreach (var item in staffList1)
                        {
                            UserName += item.FirstName + " " + item.LastName + ",";
                        }
                        UserName = UserName.TrimEnd(',');
                    }
                }
                else
                {
                    if (roles.Contains("FacilityStaff"))
                    {
                        var staffList = _dBContext.FacilityStaffs.Where(x => x.UserID == user.Id).ToList();
                        foreach (var item in staffList)
                        {
                            UserName += item.FirstName + " " + item.LastName + ",";
                        }
                        //UserName = UserName.TrimEnd(',');
                    }
                    if (roles.Contains("DoctorStaff"))
                    {
                        var staffList1 = _dBContext.DoctorStaffs.Where(x => x.UserID == user.Id).ToList();
                        foreach (var item in staffList1)
                        {
                            UserName += item.FirstName + " " + item.LastName + ",";
                        }
                        
                    }
                    UserName = UserName.TrimEnd(',');
                }
                string mailTo = user.Email;
                string strSubject = "NorthStarHub: Password Reset";
                string Tempbody = "";
                var fileProvider = _environment.WebRootFileProvider;

                // here you define only subpath

                var fileInfo = fileProvider.GetFileInfo("/EmailTemplates/ForgotPassword.html");
                var fileStream = fileInfo.CreateReadStream();
                using (var reader = new StreamReader(fileStream))
                {
                    Tempbody = reader.ReadToEnd();
                }
                string strBody = String.Format(Tempbody, UserName, password);

                //  send Mail
                var res = await SendMailWithoutAttachment("", "", mailTo, strSubject, strBody);
                if(res)
                {
                    return RedirectToAction(nameof(Login), new { returnUrl = returnUrl, IsPasswordReset = true });
                }
                else
                {

                    return RedirectToAction(nameof(Login), new { returnUrl = returnUrl, IsPasswordReset = false });
                }
                //else
                //    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                //var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
                //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                //   $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                //return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        private static string CreateRandomPassword(int passwordLength)
        {
            string allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789!@$?_-";
            char[] chars = new char[passwordLength];
            Random rd = new Random();

            for (int i = 0; i < passwordLength; i++)
            {
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
            }

            return new string(chars);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("A code must be supplied for password reset.");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }


        private async Task<bool> AddAppointment(object appointment)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Clear();
                var res= await client.PostAsJsonAsync("https://msh2commonapi.azurewebsites.net/api/Common/PostAppointmentDataFromWebsite", appointment);
                if (res.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }
        #endregion

        /// <summary>
        ///    Send mail without attachment
        /// </summary>
        /// <param name="ToEmail"></param>
        /// <param name="ToBCCEmail"></param>
        /// <param name="ToCCEmail"></param>
        /// <param name="Subject"></param>
        /// <param name="Body"></param>
        /// <returns></returns>
        public async Task<bool> SendMailWithoutAttachment(string ToBCCEmail, string ToCCEmail, string ToEmail, string Subject, string Body)
        {
            MailMessage mail = new MailMessage();
            mail.To.Add(ToEmail);
            if (!string.IsNullOrWhiteSpace(ToBCCEmail))
            {
                mail.Bcc.Add(new MailAddress(ToBCCEmail.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(ToCCEmail))
            {
                mail.CC.Add(new MailAddress(ToCCEmail.Trim()));
            }

            // mail.From = new MailAddress("donotreply@ansitian.com", "NorthStarHub", System.Text.Encoding.UTF8);
            mail.From = new MailAddress("donotreply@ansitian.com", "NorthStarHub", System.Text.Encoding.UTF8);
            mail.Subject = Subject;
            mail.SubjectEncoding = System.Text.Encoding.UTF8;
            mail.Body = Body;
            mail.BodyEncoding = System.Text.Encoding.UTF8;
            mail.IsBodyHtml = true;
            mail.Priority = MailPriority.High;

            SmtpClient client = new SmtpClient()
            {
                //Host = "mail.ansitian.com",
                //Port = 8889,
                Host = "mail.ansitian.com",
                Port = 8889,
                EnableSsl = false,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential("donotreply@ansitian.com", "lndia@gr8")
                //Credentials = new NetworkCredential("donotreply@ansitian.com", "lndia@gr8")

            };

            try
            {
                await client.SendMailAsync(mail);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        //public ActionResult Login_Exist_Doctorstaff(string Email,string password)
        //{
        //    //string password = Convert.ToString(Session["CurrentPassword"]);
        //    var users = _repo.GetAllUserByEmailandpassword(Email, password);
        //    if (users.Count > 0)
        //    {
        //        int doctorStaffUserTypeId = ConstantHelper.GetUserTypeID(UserTypeConstant.DoctorStaffUserType);
        //        int DocReferralStaff = ConstantHelper.GetUserTypeID(UserTypeConstant.DoctorReferralSpecialistStaffUserType);
        //        int facilityStaffUserTypeId = ConstantHelper.GetUserTypeID(UserTypeConstant.DiagnosticLabStaffUserType);
        //        int FacilityReferralStaff = ConstantHelper.GetUserTypeID(UserTypeConstant.FacilityReferralSpecialistStaffUserType);
        //        int ReferralSpecialistManagerUserType = ConstantHelper.GetUserTypeID(UserTypeConstant.ReferralSpecialistManagerUserType);
        //        int ReferralSpecialistUserType = ConstantHelper.GetUserTypeID(UserTypeConstant.ReferralSpecialistUserType);
        //        int CustomerSupportRepresentative = ConstantHelper.GetUserTypeID(UserTypeConstant.CustomerSupportRepresentative);
        //        int AdminUserType = ConstantHelper.GetUserTypeID(UserTypeConstant.AdminUserType);
        //        foreach (var item in users)
        //        {
        //            item.EncryptedID = QueryStringManager.Encrypt(Convert.ToInt32(item.ID));
        //            if (item.UserTypeID == doctorStaffUserTypeId || item.UserTypeID == DocReferralStaff)
        //            {
        //                var staff = _doctorStaffRepo.GetStaffByLoginID(item.ID);
        //                if (staff != null)
        //                {
        //                    var doctors = _repo.GetDoctorByID(staff.DoctorID ?? 0);
        //                    item.LoginAs = doctors.Name;
        //                }

        //            }
        //            else if (item.UserTypeID == facilityStaffUserTypeId || item.UserTypeID == FacilityReferralStaff)
        //            {
        //                var staff = _diagnosticRepo.GetStaffByLoginID(item.ID);
        //                var doctors = _diagnosticRepo.GetDiagnosticByID(staff.FacilityID ?? 0);
        //                item.LoginAs = doctors.Name;
        //            }

        //        }
        //        users = users.Where(x => x.UserTypeID != ReferralSpecialistUserType && x.UserTypeID != ReferralSpecialistManagerUserType && x.UserTypeID != CustomerSupportRepresentative && x.UserTypeID != AdminUserType).ToList();
        //        ViewBag.Users = users;
        //    }
        //    else
        //    {
        //        return RedirectToAction("Index", "Elite");
        //    }

        //    return View();
        //}
        [HttpGet]
        public async Task<IActionResult> RoleManager()
        {
            List<RoleManagerModel> roleManagers = new List<RoleManagerModel>();
            var userid = HttpContext.Session.GetString(SessionName);
            var userlist = await _userManager.FindByIdAsync(userId: userid);
            var roleList = await _userManager.GetRolesAsync(userlist);
            var ProvideTypeIDList = _dBContext.ApplicationRoles.ToList();
            if(roleList != null && roleList.Count() > 0)
            {
               
                if (roleList.Contains("FacilityStaff"))
                {
                    roleManagers = _dBContext.FacilityStaffs.Where(x => x.UserID == userid && x.RecordStatus == RecordStatusConstants.Active).Select(y => new RoleManagerModel() {

                        MainId = y.ID,
                        ProviderName = y.Facility.FacilityName,
                        ProviderRole= "FacilityStaff",
                        providerId = y.FacilityID,
                        ProviderTypeId = ProvideTypeIDList.Where(p =>p.Name == "FacilityStaff").Select(p =>p.Id).FirstOrDefault(),
                        LoginUserName = y.FirstName+" "+y.LastName

                    }).ToList();
                }
                if(roleList.Contains("DoctorStaff"))
                {
                    var doctorstafflist = _dBContext.DoctorStaffs.Where(x => x.UserID == userid && x.RecordStatus == RecordStatusConstants.Active).Select(z => new RoleManagerModel() {

                        MainId = z.ID,
                        ProviderName = z.Doctor.FirstName +" "+z.Doctor.LastName,
                        ProviderRole = "DoctorStaff",
                        providerId = z.DoctorID,
                        ProviderTypeId = ProvideTypeIDList.Where(p => p.Name == "DoctorStaff").Select(p => p.Id).FirstOrDefault(),
                        LoginUserName = z.FirstName + " " + z.LastName
                    }).ToList();
                    roleManagers.AddRange(doctorstafflist);
                }


            }
            return View(roleManagers);
        }
        [HttpPost]
        public async Task<IActionResult> ConfirmEmailForForgotPass(string Email)
        {
           
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                return Json("Email not exist");
            }

            return Json("Exist");
        }
        [AllowAnonymous]
        [HttpGet]
        public JsonResult CheckUserLoginPatient(string userName)
        {
            try
            {
                List<ApplicationUser> user = new List<ApplicationUser>();
                if (userName.Contains("@") && userName.Contains("."))
                {
                    user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.Email.ToLower() == userName.ToLower() && x.IsUserActive).ToList();
                    //user = await _userManager.FindByEmailAsync(userName);
                }
                else
                {
                    user = _dBContext.ApplicationUsers.Where(x => !x.IsNewUsers && x.PhoneNumber == userName && x.IsUserActive).ToList();
                }
                if (user.Count() > 1)
                {
                    return Json(new { singleUser = true });
                }
                else
                {
                    return Json(new { singleUser = false });
                }
            }
            catch (Exception ex)
            {
                return Json(new { singleUser = false });
                //return Json("");
            }
        }
    }
}
