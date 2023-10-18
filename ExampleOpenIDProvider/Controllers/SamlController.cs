using ComponentSpace.Saml2;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExampleOpenIDProvider.Controllers
{
    [Route("[controller]/[action]")]
    public class SamlController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISamlServiceProvider _samlServiceProvider;
        private readonly IConfiguration _configuration;

        public SamlController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ISamlServiceProvider samlServiceProvider,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _samlServiceProvider = samlServiceProvider;
            _configuration = configuration;
        }

        public async Task<IActionResult> InitiateSingleSignOnAsync(string? returnUrl = null)
        {
            var partnerName = _configuration["PartnerName"];

            // To login automatically at the service provider, 
            // initiate single sign-on to the identity provider (SP-initiated SSO).            
            // The return URL is remembered as SAML relay state.
            await _samlServiceProvider.InitiateSsoAsync(partnerName, returnUrl);

            return new EmptyResult();
        }

        public async Task<IActionResult> InitiateSingleLogoutAsync(string? returnUrl = null)
        {
            // Request logout at the identity provider.
            await _samlServiceProvider.InitiateSloAsync(relayState: returnUrl);

            return new EmptyResult();
        }

        public async Task<IActionResult> AssertionConsumerServiceAsync()
        {
            // Receive and process the SAML assertion contained in the SAML response.
            // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
            var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

            // Automatically provision the user.
            // If the user doesn't exist locally then create the user.
            // Automatic provisioning is an optional step.
            var user = await _userManager.FindByNameAsync(ssoResult.UserID);

            if (user == null)
            {
                user = new IdentityUser { UserName = ssoResult.UserID, Email = ssoResult.UserID };

                var result = await _userManager.CreateAsync(user);

                if (!result.Succeeded)
                {
                    throw new Exception($"The user {ssoResult.UserID} couldn't be created - {result}");
                }

                // For demonstration purposes, create some additional claims.
                if (ssoResult.Attributes != null)
                {
                    var samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Email);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Email, samlAttribute.ToString()));
                    }

                    samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.GivenName);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.GivenName, samlAttribute.ToString()));
                    }

                    samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Surname);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Surname, samlAttribute.ToString()));
                    }
                }
            }

            // Automatically login using the asserted identity.
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Redirect to the target URL if specified.
            if (!string.IsNullOrEmpty(ssoResult.RelayState))
            {
                return LocalRedirect(ssoResult.RelayState);
            }

            return RedirectToPage("/Index");
        }

        public async Task<IActionResult> SingleLogoutServiceAsync()
        {
            // Receive the single logout request or response.
            // If a request is received then single logout is being initiated by the identity provider.
            // If a response is received then this is in response to single logout having been initiated by the service provider.
            var sloResult = await _samlServiceProvider.ReceiveSloAsync();

            if (sloResult.IsResponse)
            {
                // SP-initiated SLO has completed.
                if (!string.IsNullOrEmpty(sloResult.RelayState))
                {
                    return LocalRedirect(sloResult.RelayState);
                }

                return RedirectToPage("/Index");
            }
            else
            {
                // Logout locally.
                await _signInManager.SignOutAsync();

                // Respond to the IdP-initiated SLO request indicating successful logout.
                await _samlServiceProvider.SendSloAsync();
            }

            return new EmptyResult();
        }
    }
}
