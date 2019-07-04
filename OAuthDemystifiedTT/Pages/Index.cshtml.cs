using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OAuthDemystifiedTT.Pages
{
    public class IndexModel : PageModel
    {
        public List<string> variables = new List<string>();
        public void OnGet()
        {
            foreach (string key in Environment.GetEnvironmentVariables().Keys)
            {
                variables.Add($"{key} : {Environment.GetEnvironmentVariable(key)}");
            }
        }
    }
}
