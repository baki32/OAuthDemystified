using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthDemystifiedTT
{
    public class ValidAADTokenRequirement : IAuthorizationRequirement
    {
        public ValidAADTokenRequirement()
        {
        }
    }

    public class ValidAADTokenHandler : AuthorizationHandler<ValidAADTokenRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                       ValidAADTokenRequirement requirement)
        {
            if (context.Resource is AuthorizationFilterContext mvcContext)
            {
                var req = mvcContext.HttpContext.Request;
                // Examine MVC-specific things like routing data.
            }
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
