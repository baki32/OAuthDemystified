using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Internal;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace OauthHandler
{
    public class OauthConnectHandler : RemoteAuthenticationHandler<OauthConnectOptions>, IAuthenticationSignOutHandler
    {
        protected HtmlEncoder HtmlEncoder { get; }
        public OauthConnectHandler(IOptionsMonitor<OauthConnectOptions> options, ILoggerFactory logger, HtmlEncoder htmlEncoder, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            HtmlEncoder = htmlEncoder;
        }

    protected override string ClaimsIssuer => base.ClaimsIssuer;

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override Task<bool> HandleRequestAsync()
        {
            return base.HandleRequestAsync();
        }

        public override Task<bool> ShouldHandleRequestAsync()
        {
            return base.ShouldHandleRequestAsync();
        }

        public Task SignOutAsync(AuthenticationProperties properties)
        {
            throw new NotImplementedException();
        }

        public override string ToString()
        {
            return base.ToString();
        }

        protected override Task<object> CreateEventsAsync()
        {
            return base.CreateEventsAsync();
        }

        protected override void GenerateCorrelationId(AuthenticationProperties properties)
        {
            base.GenerateCorrelationId(properties);
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return base.HandleAuthenticateAsync();
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var url = $"https://login.microsoftonline.com/9fc05d5c-d237-4598-9f9c-65b71fb914ab/oauth2/authorize" +
                    $"?client_id=eb28e386-ad93-429e-9820-4c7e9b7152d5" +
                    $"&response_type=code" +
                    $"&redirect_uri={HtmlEncoder.Default.Encode("https://localhost:44337/signin-oidc")}" +
                    $"&response_mode=form_post" +
                    // VERY SIMPLIFIED but .net core is doing it in similar way using state param => store redirect URL in state, either take what's in properties or store current action URL
                    $"&state={properties.RedirectUri ?? $"{ new Uri(new Uri(this.Context.Request.Headers["Referer"]), this.Context.Request.Path.Value)}"}";
            Response.Redirect(url);
            return Task.CompletedTask;
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            return base.HandleForbiddenAsync(properties);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var properties = new AuthenticationProperties();
            var form = await Request.ReadFormAsync();
            var http = new HttpClient();
            http.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
            var resp = await http.PostAsync("https://login.microsoftonline.com/9fc05d5c-d237-4598-9f9c-65b71fb914ab/oauth2/token",
                new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("client_id", "eb28e386-ad93-429e-9820-4c7e9b7152d5"),
                    new KeyValuePair<string, string>("code", form["code"]),
                    new KeyValuePair<string, string>("redirect_uri", "https://localhost:44337/signin-oidc"),
                    new KeyValuePair<string, string>("client_secret", "VfZbajtpKNdQwsDw9kJ6v8ghG9Gx4J/i5/58BoSuTao=")
                }
               ));
            var content = await resp.Content.ReadAsStringAsync();
            
            var authorizationResponse = new OpenIdConnectMessage(content);
            //retrieve redirect URL
            properties.RedirectUri = form["state"];

            SecurityToken validatedToken;
            var validationParameters = new TokenValidationParameters();
            validationParameters.ValidateAudience = false;
            validationParameters.ValidateIssuer = false;
            validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(Options.Configuration.SigningKeys)
                ?? Options.Configuration.SigningKeys;
            var validatedTokenResponse = Options.SecurityTokenValidator.ValidateToken(authorizationResponse.AccessToken, validationParameters, out validatedToken);
            //authorizationResponse = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));

            var msg = new OpenIdConnectMessage
            {
                AccessToken = authorizationResponse.AccessToken,
                IdToken = authorizationResponse.IdToken,
                RefreshToken = authorizationResponse.RefreshToken,
                ExpiresIn = authorizationResponse.ExpiresIn,
                RedirectUri = authorizationResponse.RedirectUri
            };

            SaveTokens(properties, msg);

            return HandleRequestResult.Success(new AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(validatedTokenResponse.Identity), properties, Scheme.Name));
        }

        protected override Task InitializeEventsAsync()
        {
            return base.InitializeEventsAsync();
        }

        protected override Task InitializeHandlerAsync()
        {
            return base.InitializeHandlerAsync();
        }

        protected override string ResolveTarget(string scheme)
        {
            return base.ResolveTarget(scheme);
        }

        protected override bool ValidateCorrelationId(AuthenticationProperties properties)
        {
            return base.ValidateCorrelationId(properties);
        }

        private void SaveTokens(AuthenticationProperties properties, OpenIdConnectMessage message)
        {
            var tokens = new List<AuthenticationToken>();

            if (!string.IsNullOrEmpty(message.AccessToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.AccessToken, Value = message.AccessToken });
            }

            if (!string.IsNullOrEmpty(message.IdToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.IdToken, Value = message.IdToken });
            }

            if (!string.IsNullOrEmpty(message.RefreshToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.RefreshToken, Value = message.RefreshToken });
            }

            if (!string.IsNullOrEmpty(message.TokenType))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.TokenType, Value = message.TokenType });
            }

            if (!string.IsNullOrEmpty(message.ExpiresIn))
            {
                if (int.TryParse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                {
                    var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    tokens.Add(new AuthenticationToken { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) });
                }
            }

            properties.StoreTokens(tokens);
        }
    }

    public class OauthConnectOptions : RemoteAuthenticationOptions
    {
        public OauthConnectOptions()
        {
            CallbackPath = new PathString("/signin-oidc");
            SignedOutCallbackPath = new PathString("/signout-callback-oidc");
            RemoteSignOutPath = new PathString("/signout-oidc");

            //Events = new OpenIdConnectEvents();
            Scope.Add("openid");
            Scope.Add("profile");

            ClaimActions.DeleteClaim("nonce");
            ClaimActions.DeleteClaim("aud");
            ClaimActions.DeleteClaim("azp");
            ClaimActions.DeleteClaim("acr");
            ClaimActions.DeleteClaim("amr");
            ClaimActions.DeleteClaim("iss");
            ClaimActions.DeleteClaim("iat");
            ClaimActions.DeleteClaim("nbf");
            ClaimActions.DeleteClaim("exp");
            ClaimActions.DeleteClaim("at_hash");
            ClaimActions.DeleteClaim("c_hash");
            ClaimActions.DeleteClaim("auth_time");
            ClaimActions.DeleteClaim("ipaddr");
            ClaimActions.DeleteClaim("platf");
            ClaimActions.DeleteClaim("ver");

            // http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
            ClaimActions.MapUniqueJsonKey("sub", "sub");
            ClaimActions.MapUniqueJsonKey("name", "name");
            ClaimActions.MapUniqueJsonKey("given_name", "given_name");
            ClaimActions.MapUniqueJsonKey("family_name", "family_name");
            ClaimActions.MapUniqueJsonKey("profile", "profile");
            ClaimActions.MapUniqueJsonKey("email", "email");

            //_nonceCookieBuilder = new OpenIdConnectNonceCookieBuilder(this)
            //{
            //    Name = OpenIdConnectDefaults.CookieNoncePrefix,
            //    HttpOnly = true,
            //    SameSite = SameSiteMode.None,
            //    SecurePolicy = CookieSecurePolicy.SameAsRequest,
            //    IsEssential = true,
            //};
        }

        /// <summary>
        /// Check that the options are valid.  Should throw an exception if things are not ok.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (MaxAge.HasValue && MaxAge.Value < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(MaxAge), MaxAge.Value, "The value must not be a negative TimeSpan.");
            }

            if (string.IsNullOrEmpty(ClientId))
            {
                throw new ArgumentException("Options.ClientId must be provided", nameof(ClientId));
            }

            if (!CallbackPath.HasValue)
            {
                throw new ArgumentException("Options.CallbackPath must be provided.", nameof(CallbackPath));
            }

            if (ConfigurationManager == null)
            {
                throw new InvalidOperationException($"Provide {nameof(Authority)}, {nameof(MetadataAddress)}, "
                + $"{nameof(Configuration)}, or {nameof(ConfigurationManager)} to {nameof(OauthConnectOptions)}");
            }
        }

        /// <summary>
        /// Gets or sets the Authority to use when making OpenIdConnect calls.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets the 'client_id'.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the 'client_secret'.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Configuration provided directly by the developer. If provided, then MetadataAddress and the Backchannel properties
        /// will not be used. This information should not be updated during request processing.
        /// </summary>
        public OpenIdConnectConfiguration Configuration { get; set; }

        /// <summary>
        /// Responsible for retrieving, caching, and refreshing the configuration from metadata.
        /// If not provided, then one will be created using the MetadataAddress and Backchannel properties.
        /// </summary>
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; }

        /// <summary>
        /// Boolean to set whether the handler should go to user info endpoint to retrieve additional claims or not after creating an identity from id_token received from token endpoint.
        /// The default is 'false'.
        /// </summary>
        public bool GetClaimsFromUserInfoEndpoint { get; set; }

        /// <summary>
        /// A collection of claim actions used to select values from the json user data and create Claims.
        /// </summary>
        public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

        /// <summary>
        /// Gets or sets if HTTPS is required for the metadata address or authority.
        /// The default is true. This should be disabled only in development environments.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the discovery endpoint for obtaining metadata
        /// </summary>
        public string MetadataAddress { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="OpenIdConnectEvents"/> to notify when processing OpenIdConnect messages.
        /// </summary>
        //public new OpenIdConnectEvents Events
        //{
        //    get => (OpenIdConnectEvents)base.Events;
        //    set => base.Events = value;
        //}

        /// <summary>
        /// Gets or sets the 'max_age'. If set the 'max_age' parameter will be sent with the authentication request. If the identity
        /// provider has not actively authenticated the user within the length of time specified, the user will be prompted to
        /// re-authenticate. By default no max_age is specified.
        /// </summary>
        public TimeSpan? MaxAge { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="OpenIdConnectProtocolValidator"/> that is used to ensure that the 'id_token' received
        /// is valid per: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public OpenIdConnectProtocolValidator ProtocolValidator { get; set; } = new OpenIdConnectProtocolValidator()
        {
            RequireStateValidation = false,
            NonceLifetime = TimeSpan.FromMinutes(15)
        };

        /// <summary>
        /// The request path within the application's base path where the user agent will be returned after sign out from the identity provider.
        /// See post_logout_redirect_uri from http://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout.
        /// </summary>
        public PathString SignedOutCallbackPath { get; set; }

        /// <summary>
        /// The uri where the user agent will be redirected to after application is signed out from the identity provider.
        /// The redirect will happen after the SignedOutCallbackPath is invoked.
        /// </summary>
        /// <remarks>This URI can be out of the application's domain. By default it points to the root.</remarks>
        public string SignedOutRedirectUri { get; set; } = "/";

        /// <summary>
        /// Gets or sets if a metadata refresh should be attempted after a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
        /// recovery in the event of a signature key rollover. This is enabled by default.
        /// </summary>
        public bool RefreshOnIssuerKeyNotFound { get; set; } = true;

        /// <summary>
        /// Gets or sets the method used to redirect the user agent to the identity provider.
        /// </summary>
        //public OpenIdConnectRedirectBehavior AuthenticationMethod { get; set; } = OpenIdConnectRedirectBehavior.RedirectGet;

        /// <summary>
        /// Gets or sets the 'resource'.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// Gets or sets the 'response_mode'.
        /// </summary>
        public string ResponseMode { get; set; } = OpenIdConnectResponseMode.FormPost;

        /// <summary>
        /// Gets or sets the 'response_type'.
        /// </summary>
        public string ResponseType { get; set; } = OpenIdConnectResponseType.IdToken;

        /// <summary>
        /// Gets or sets the 'prompt'.
        /// </summary>
        public string Prompt { get; set; }

        /// <summary>
        /// Gets the list of permissions to request.
        /// </summary>
        public ICollection<string> Scope { get; } = new HashSet<string>();

        /// <summary>
        /// Requests received on this path will cause the handler to invoke SignOut using the SignOutScheme.
        /// </summary>
        public PathString RemoteSignOutPath { get; set; }

        /// <summary>
        /// The Authentication Scheme to use with SignOut on the SignOutPath. SignInScheme will be used if this
        /// is not set.
        /// </summary>
        public string SignOutScheme { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure strings used by the handler.
        /// </summary>
        public ISecureDataFormat<string> StringDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="ISecurityTokenValidator"/> used to validate identity tokens.
        /// </summary>
        public ISecurityTokenValidator SecurityTokenValidator { get; set; } = new JwtSecurityTokenHandler();

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// Indicates that the authentication session lifetime (e.g. cookies) should match that of the authentication token.
        /// If the token does not provide lifetime information then normal session lifetimes will be used.
        /// This is disabled by default.
        /// </summary>
        public bool UseTokenLifetime { get; set; }

        /// <summary>
        /// Indicates if requests to the CallbackPath may also be for other components. If enabled the handler will pass
        /// requests through that do not contain OpenIdConnect authentication responses. Disabling this and setting the
        /// CallbackPath to a dedicated endpoint may provide better error handling.
        /// This is disabled by default.
        /// </summary>
        public bool SkipUnrecognizedRequests { get; set; } = false;

        /// <summary>
        /// Indicates whether telemetry should be disabled. When this feature is enabled,
        /// the assembly version of the Microsoft IdentityModel packages is sent to the
        /// remote OpenID Connect provider as an authorization/logout request parameter.
        /// </summary>
        public bool DisableTelemetry { get; set; }

        /// <summary>
        /// Determines the settings used to create the nonce cookie before the
        /// cookie gets added to the response.
        /// </summary>
        /// <remarks>
        /// The value of <see cref="CookieBuilder.Name"/> is treated as the prefix to the cookie name, and defaults to <seealso cref="OpenIdConnectDefaults.CookieNoncePrefix"/>.
        /// </remarks>
        //public CookieBuilder NonceCookie
        //{
        //    get => _nonceCookieBuilder;
        //    set => _nonceCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
        //}

        private class OauthConnectOptionsNonceCookieBuilder : RequestPathBaseCookieBuilder
        {
            private readonly OauthConnectOptions _options;

            public OauthConnectOptionsNonceCookieBuilder(OauthConnectOptions oidcOptions)
            {
                _options = oidcOptions;
            }

            protected override string AdditionalPath => _options.CallbackPath;

            public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
            {
                var cookieOptions = base.Build(context, expiresFrom);

                if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
                {
                    cookieOptions.Expires = expiresFrom.Add(_options.ProtocolValidator.NonceLifetime);
                }

                return cookieOptions;
            }
        }
    }
}
