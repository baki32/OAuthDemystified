using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthDemystifiedTT;

namespace OAuthDemystifiedTT.Pages
{
    public class AuthgrantModel : PageModel
    {
        public string TopSecret { get; set; }
        public async Task OnGet()
        {
            try
            {
                var token = await Request.HttpContext.GetTokenAsync("access_token");
                Console.WriteLine("TOKEN: " + token);
                var http = new HttpClient();
                http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                var resp = await http.GetAsync("http://back/api/values");

                if (resp.IsSuccessStatusCode)
                {
                    var content = await resp.Content.ReadAsStringAsync();
                    TopSecret = content;
                }
                else
                {
                    await Request.HttpContext.ChallengeAsync(
                        "TechtalkScheme",
                        new AuthenticationProperties { RedirectUri = Url.Content("~/Authgrant") });
                }
            }
            catch (Exception ex)
            {

                throw new Exception("JA NEVIEM US" + ex.ToString());
            }
        }
    }
}