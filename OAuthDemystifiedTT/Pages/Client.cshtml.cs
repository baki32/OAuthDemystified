using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OAuthDemystifiedTT.Pages
{
    public class ClientModel : PageModel
    {
        public string TopSecret { get; set; }
        public async Task OnGet()
        {
            var accessToken = "";
            try
            {
                var token = string.Empty;
                var clnt = new HttpClient();
                var rsp = await clnt.PostAsync("https://login.microsoftonline.com/9fc05d5c-d237-4598-9f9c-65b71fb914ab/oauth2/token",
                    new StringContent(
                        "resource=https://graph.windows.net" +
                        "&scope=User.Read" +
                        "&grant_type=client_credentials" +
                        "&client_id=eb28e386-ad93-429e-9820-4c7e9b7152d5" +
                        $"&client_secret={HtmlEncoder.Default.Encode("Vpr4gYm1O5aVjYzELlO0zOW0tJv8kElq/UelqLNnDV8=")}",
                    Encoding.UTF8,
                    "application/x-www-form-urlencoded"));


                if (rsp.IsSuccessStatusCode)
                {
                    var str = await rsp.Content.ReadAsStringAsync();
                    var authorizationResponse = new OpenIdConnectMessage(str);

                    var http = new HttpClient();
                    accessToken = authorizationResponse.AccessToken;
                    http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                    var resp = await http.GetAsync("http://back/api/values");
                    var content = await resp.Content.ReadAsStringAsync();
                    TopSecret = content;
                }
            }
            catch (Exception ex)
            {

                throw new Exception("JA NEVIEM US http://back:8080/api/values " + ex.ToString() + " " + accessToken);
            }


        }
    }
}