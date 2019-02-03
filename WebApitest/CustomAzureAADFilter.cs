using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
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
            try
            {
                if (context.Resource is AuthorizationFilterContext mvcContext)
                {
                    var req = mvcContext.HttpContext.Request;

                    string stsDiscoveryEndpoint = "https://login.microsoftonline.com/ibmke.onmicrosoft.com/v2.0/.well-known/openid-configuration";

                    var ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());

                    var Configuration = ConfigurationManager.GetConfigurationAsync(CancellationToken.None).Result;

                    SecurityToken validatedToken;
                    var validationParameters = new TokenValidationParameters();
                    validationParameters.ValidateAudience = false;
                    validationParameters.ValidateIssuer = false;
                    validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(Configuration.SigningKeys)
                        ?? Configuration.SigningKeys;
                    var validatedTokenResponse = new JwtSecurityTokenHandler().ValidateToken(req.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty), validationParameters, out validatedToken);
                }
                context.Succeed(requirement);
            }
            catch
            {
                context.Fail();
            }
            return Task.CompletedTask;
        }
    }
}
