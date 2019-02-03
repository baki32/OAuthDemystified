using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static Microsoft.AspNetCore.Hosting.Internal.HostingApplication;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace OAuthDemystifiedTT.Controllers
{
    [Route("Login")]
    [AllowAnonymous]
    public class LoginController : Controller
    {
        // GET: /<controller>/
        //[HttpGet]
        //[Route("SignIn")]
        //public IActionResult SignIn()
        //{
        //    return Challenge();
        //    //var url = $"https://login.microsoftonline.com/9fc05d5c-d237-4598-9f9c-65b71fb914ab/oauth2/authorize" +
        //    //    $"?client_id=eb28e386-ad93-429e-9820-4c7e9b7152d5" +
        //    //    $"&response_type=code" +
        //    //    $"&redirect_uri={HttpUtility.UrlEncode("https://localhost:44337/Login/ProcessIDToken")}" +
        //    //    $"&response_mode=form_post";
        //    //return Redirect(url);
        //}

        [HttpGet("{scheme?}")]
        public IActionResult SignIn([FromRoute] string scheme)
        {
            scheme = scheme ?? "TechtalkScheme";
            var redirectUrl = Url.Content("~/");
            return Challenge(
                new AuthenticationProperties { RedirectUri = redirectUrl },
                scheme);
        }

        [HttpGet]
        [Route("SignOut")]
        public async Task SignOut()
        {
            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Response.Redirect("/");
            return;
        }

        [HttpPost]
        [Route("ProcessIDToken")]
        public async Task<IActionResult> ProcessIDToken()
        {            
            var http = new HttpClient();
            http.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
            var resp = await http.PostAsync("https://login.microsoftonline.com/9fc05d5c-d237-4598-9f9c-65b71fb914ab/oauth2/token",
                new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("client_id", "eb28e386-ad93-429e-9820-4c7e9b7152d5"),                    
                    new KeyValuePair<string, string>("code", Request.Form["code"]),
                    new KeyValuePair<string, string>("redirect_uri", "https://localhost:44337/Login/ProcessIDToken"),
                    new KeyValuePair<string, string>("client_secret", "VfZbajtpKNdQwsDw9kJ6v8ghG9Gx4J/i5/58BoSuTao=")
                }
                //    $"grant_type=authorization_code" +
                //$"&client_id=eb28e386-ad93-429e-9820-4c7e9b7152d5" +
                //$"&code={Request.Form["code"]}" +
                //$"&redirect_uri={HttpUtility.UrlEncode("https://localhost:44337/Login/ProcessIDToken")}" +
                //$"&client_secret=VfZbajtpKNdQwsDw9kJ6v8ghG9Gx4J/i5/58BoSuTao="
               ));
            var cotnent = await resp.Content.ReadAsStringAsync();
            return Ok();
        }


    }
}
