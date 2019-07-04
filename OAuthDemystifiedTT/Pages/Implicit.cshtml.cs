using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OAuthDemystifiedTT.Pages
{
    public class ImplicitModel : PageModel
    {
        public string url {
            get {
                return HtmlEncoder.Default.Encode($"{Environment.GetEnvironmentVariable("PROTOCOL") ?? "http"}://{this.Request.Host}");
            }
        }
        public void OnGet()
        {
        }
    }
}