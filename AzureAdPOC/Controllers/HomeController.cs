using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using AzureAdPOC.Models;

namespace ADDemo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View("~/Views/Home/Login.cshtml");
        }

        [HttpPost]
        public IActionResult LoginWithAD()
        {
            // It triggers an authentication challenge. This asks the user to authenticate themselves
            // The Challenge method is part of the ASP.NET Core's Authentication Middleware,
            // initiates the process of redirecting the user to the configured identity provider (in this case, Azure AD via OpenID Connect).
            // AuthenticationProperties sets additional behavior for the authentication challenge.
            // RedirectUri: Indicates where the user will be redirected after successfully logging in via Azure AD.
            // OpenIdConnectDefaults.AuthenticationScheme specifies the authentication scheme being used.
            return Challenge(new AuthenticationProperties() { RedirectUri = "/Home/AfterADLogin" }, 
                OpenIdConnectDefaults.AuthenticationScheme);
        }


        public IActionResult AfterADLogin()
        {
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> CustomLogin(string username, string password)
        {
            if (username == "user1" && password == "Password@1")
            {
                // Call API to generate token
                var token = await ApiTokenGenerator.GetTokenFromApi(
                    _configuration["ApiUrl"] + "/api/auth/login",
                    new { Username = username, Password = password });

                if (!string.IsNullOrEmpty(token))
                {
                    HttpContext.Session.SetString("JwtToken", token);
                    return RedirectToAction("Index");
                }
            }

            return Unauthorized();
        }

        [Authorize]
        public IActionResult Secured()
        {
            return Ok("Secured Resource");
        }

        public async Task<IActionResult> Logout()
        {
            HttpContext.Session.Remove("JwtToken");

            // Check if the user was authenticated using OpenID Connect (Azure AD)
            if (User.Identity.AuthenticationType == OpenIdConnectDefaults.AuthenticationScheme)
            {
                // Sign out using OpenID Connect
                await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
            }
            else
            {
                // Sign out using cookie authentication (for custom JWT)
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            return Redirect("/");
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}